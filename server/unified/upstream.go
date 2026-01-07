package unified

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"sync"

	"github.com/andydunstall/yamux"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/andydunstall/piko/pkg/auth"
	"github.com/andydunstall/piko/pkg/log"
	"github.com/andydunstall/piko/pkg/middleware"
	pikowebsocket "github.com/andydunstall/piko/pkg/websocket"
	"github.com/andydunstall/piko/server/cluster"
	"github.com/andydunstall/piko/server/config"
	"github.com/andydunstall/piko/server/upstream"
)

// upstreamHandler handles WebSocket connections from upstream agents.
type upstreamHandler struct {
	upstreams upstream.Manager

	sessions   map[*yamux.Session]struct{}
	sessionsMu sync.Mutex

	websocketUpgrader *websocket.Upgrader

	ctx    context.Context
	cancel func()

	cluster *cluster.State

	verifier *auth.MultiTenantVerifier

	config config.UpstreamConfig

	logger log.Logger
}

func newUpstreamHandler(
	upstreams upstream.Manager,
	verifier *auth.MultiTenantVerifier,
	cluster *cluster.State,
	config config.UpstreamConfig,
	logger log.Logger,
) *upstreamHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &upstreamHandler{
		upstreams:         upstreams,
		sessions:          make(map[*yamux.Session]struct{}),
		websocketUpgrader: &websocket.Upgrader{},
		ctx:               ctx,
		cancel:            cancel,
		cluster:           cluster,
		verifier:          verifier,
		config:            config,
		logger:            logger.WithSubsystem("upstream"),
	}
}

func (h *upstreamHandler) handleRequest(c *gin.Context) {
	// Apply auth middleware if configured
	if h.verifier != nil {
		authMiddleware := middleware.NewAuth(h.verifier, h.logger)
		authMiddleware.Verify(c)
		if c.IsAborted() {
			return
		}
	}

	// Extract endpoint ID from path: /piko/v1/upstream/:endpointID
	path := c.Request.URL.Path
	const prefix = "/piko/v1/upstream/"
	if len(path) <= len(prefix) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing endpoint id"})
		return
	}
	endpointID := path[len(prefix):]

	h.handleUpstream(c, endpointID)
}

func (h *upstreamHandler) handleUpstream(c *gin.Context, endpointID string) {
	var tenantID string
	token, ok := c.Get(middleware.TokenContextKey)
	if ok {
		endpointToken := token.(*auth.Token)
		if !endpointToken.EndpointPermitted(endpointID) {
			h.logger.Warn(
				"endpoint not permitted",
				zap.Strings("token-endpoints", endpointToken.Endpoints),
				zap.String("endpoint-id", endpointID),
			)
			c.JSON(
				http.StatusUnauthorized,
				gin.H{"error": "endpoint not permitted"},
			)
			return
		}
		tenantID = endpointToken.TenantID
	}

	wsConn, err := h.websocketUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Warn("failed to upgrade websocket", zap.Error(err))
		return
	}
	conn := pikowebsocket.New(wsConn)
	defer conn.Close()

	h.logger.Info(
		"upstream connected",
		zap.String("endpoint-id", endpointID),
		zap.String("client-ip", c.ClientIP()),
		zap.String("tenant-id", tenantID),
	)
	defer h.logger.Info(
		"upstream disconnected",
		zap.String("endpoint-id", endpointID),
		zap.String("client-ip", c.ClientIP()),
		zap.String("tenant-id", tenantID),
	)

	ctx := h.ctx
	if ok {
		endpointToken := token.(*auth.Token)
		if !endpointToken.Expiry.IsZero() {
			var cancel func()
			ctx, cancel = context.WithDeadline(ctx, endpointToken.Expiry)
			defer cancel()
		}
	}

	muxConfig := yamux.DefaultConfig()
	muxConfig.Logger = h.logger.StdLogger(zap.WarnLevel)
	muxConfig.LogOutput = nil
	sess, err := yamux.Server(conn, muxConfig)
	if err != nil {
		panic("yamux server: " + err.Error())
	}
	defer sess.Close()

	h.addSession(sess)
	defer h.removeSession(sess)

	upstreamConn := upstream.NewConnUpstream(endpointID, sess)

	h.upstreams.AddConn(upstreamConn)
	defer h.upstreams.RemoveConn(upstreamConn)

	for {
		if _, err := sess.AcceptStreamWithContext(ctx); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if errors.Is(err, context.Canceled) {
				return
			}
			if errors.Is(err, context.DeadlineExceeded) {
				h.logger.Info("upstream token expired")
				return
			}
			if errors.Is(err, yamux.ErrSessionShutdown) {
				return
			}
			h.logger.Warn("session closed unexpectedly", zap.Error(err))
			return
		}
	}
}

func (h *upstreamHandler) shutdown() {
	h.cancel()
}

func (h *upstreamHandler) rebalance() {
	if len(h.cluster.Nodes()) <= 1 {
		h.logger.Debug("rebalance; skip; no other nodes")
		return
	}

	localConns := h.openSessions()
	if localConns == 0 || localConns < int(h.config.Rebalance.MinConns) {
		h.logger.Debug(
			"rebalance; skip; too few conns",
			zap.Int("local_conns", localConns),
		)
		return
	}

	avgConns := h.cluster.AvgConns()
	balance := float64(localConns-avgConns) / float64(avgConns)
	if balance < h.config.Rebalance.Threshold {
		h.logger.Debug(
			"rebalance; skip; below threshold",
			zap.String("balance", fmt.Sprintf("%.2f", balance)),
			zap.Float64("threshold", h.config.Rebalance.Threshold),
			zap.Int("local_conns", localConns),
			zap.Int("avg_conns", avgConns),
		)
		return
	}

	shedding := float64(localConns) * balance
	if shedding > float64(avgConns)*h.config.Rebalance.ShedRate {
		shedding = math.Ceil(float64(avgConns) * h.config.Rebalance.ShedRate)
	}

	h.logger.Info(
		"rebalance; shedding connections",
		zap.Int("shedding", int(shedding)),
		zap.String("balance", fmt.Sprintf("%.2f", balance)),
		zap.Float64("threshold", h.config.Rebalance.Threshold),
		zap.Int("local_conns", localConns),
		zap.Int("avg_conns", avgConns),
	)
	h.shedSessions(int(shedding))
}

func (h *upstreamHandler) addSession(sess *yamux.Session) {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	h.sessions[sess] = struct{}{}
}

func (h *upstreamHandler) removeSession(sess *yamux.Session) {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	delete(h.sessions, sess)
}

func (h *upstreamHandler) openSessions() int {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	return len(h.sessions)
}

func (h *upstreamHandler) shedSessions(n int) {
	h.sessionsMu.Lock()
	var shedding []*yamux.Session
	for sess := range h.sessions {
		shedding = append(shedding, sess)
		if len(shedding) >= n {
			break
		}
	}
	h.sessionsMu.Unlock()

	for _, sess := range shedding {
		sess.Close()
	}
}

