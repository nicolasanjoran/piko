package unified

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/andydunstall/piko/pkg/auth"
	"github.com/andydunstall/piko/pkg/log"
	"github.com/andydunstall/piko/pkg/middleware"
	"github.com/andydunstall/piko/server/cluster"
	"github.com/andydunstall/piko/server/config"
	"github.com/andydunstall/piko/server/proxy"
	"github.com/andydunstall/piko/server/upstream"
)

// Server is a unified server that combines proxy and upstream on a single port.
// Routing is based on the domain:
// - Requests to the upstream domain are handled as agent WebSocket connections
// - Requests to any other domain are proxied to registered services
type Server struct {
	proxyHandler    *proxy.HTTPProxy
	tcpProxy        *proxy.TCPProxy
	upstreamHandler *upstreamHandler

	httpServer *http.Server
	acmeConfig *config.ACMEConfig

	logger log.Logger
}

// NewServer creates a unified server.
func NewServer(
	upstreams upstream.Manager,
	proxyConfig config.ProxyConfig,
	upstreamConfig config.UpstreamConfig,
	acmeConfig *config.ACMEConfig,
	registry *prometheus.Registry,
	proxyVerifier *auth.MultiTenantVerifier,
	upstreamVerifier *auth.MultiTenantVerifier,
	tlsConfig *tls.Config,
	clusterState *cluster.State,
	logger log.Logger,
) *Server {
	logger = logger.WithSubsystem("unified")

	httpProxy := proxy.NewHTTPProxy(upstreams, proxyConfig.Timeout, logger)

	router := gin.New()
	s := &Server{
		proxyHandler: httpProxy,
		tcpProxy:     proxy.NewTCPProxy(upstreams, httpProxy, logger),
		upstreamHandler: newUpstreamHandler(
			upstreams,
			upstreamVerifier,
			clusterState,
			upstreamConfig,
			logger,
		),
		httpServer: &http.Server{
			Handler:           router,
			TLSConfig:         tlsConfig,
			ReadTimeout:       proxyConfig.HTTP.ReadTimeout,
			ReadHeaderTimeout: proxyConfig.HTTP.ReadHeaderTimeout,
			WriteTimeout:      proxyConfig.HTTP.WriteTimeout,
			IdleTimeout:       proxyConfig.HTTP.IdleTimeout,
			MaxHeaderBytes:    proxyConfig.HTTP.MaxHeaderBytes,
			ErrorLog:          logger.StdLogger(zapcore.WarnLevel),
		},
		acmeConfig: acmeConfig,
		logger:     logger,
	}

	// Recover from panics.
	router.Use(gin.CustomRecoveryWithWriter(nil, s.panicRoute))

	// Domain-based routing middleware
	router.Use(s.domainRouter(proxyVerifier, proxyConfig))

	return s
}

func (s *Server) Serve(ln net.Listener) error {
	s.logger.Info(
		"starting unified server",
		zap.String("addr", ln.Addr().String()),
		zap.String("upstream_domain", s.acmeConfig.UpstreamDomain),
	)

	var err error
	if s.httpServer.TLSConfig != nil {
		err = s.httpServer.ServeTLS(ln, "", "")
	} else {
		err = s.httpServer.Serve(ln)
	}

	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http serve: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.upstreamHandler.shutdown()
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Rebalance() {
	s.upstreamHandler.rebalance()
}

// domainRouter returns middleware that routes requests based on domain.
func (s *Server) domainRouter(proxyVerifier *auth.MultiTenantVerifier, proxyConfig config.ProxyConfig) gin.HandlerFunc {
	// Create middleware for proxy requests
	var proxyMiddleware []gin.HandlerFunc
	if proxyVerifier != nil {
		authMiddleware := middleware.NewAuth(proxyVerifier, s.logger)
		proxyMiddleware = append(proxyMiddleware, authMiddleware.Verify)
	}
	proxyMiddleware = append(proxyMiddleware, middleware.NewLogger(proxyConfig.AccessLog, s.logger))

	return func(c *gin.Context) {
		host := c.Request.Host
		// Strip port if present
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		if host == s.acmeConfig.UpstreamDomain {
			// Route to upstream handler (agent connections)
			s.upstreamHandler.handleRequest(c)
			c.Abort()
			return
		}

		// Apply proxy middleware and route to proxy
		for _, m := range proxyMiddleware {
			m(c)
			if c.IsAborted() {
				return
			}
		}
		s.handleProxyRequest(c)
	}
}

func (s *Server) handleProxyRequest(c *gin.Context) {
	// Check for TCP proxy request
	if c.Request.URL.Path == "/_piko/v1/tcp/"+c.Param("endpointID") {
		s.proxyTCPRoute(c)
		return
	}

	// Handle HTTP proxy
	s.proxyHTTPRoute(c)
}

func (s *Server) proxyHTTPRoute(c *gin.Context) {
	endpointID := proxy.EndpointIDFromRequest(c.Request, s.acmeConfig)
	if endpointID == "" {
		s.logger.Warn("request missing endpoint id")
		c.JSON(
			http.StatusBadRequest,
			gin.H{"error": "missing endpoint id"},
		)
		return
	}

	// Verify the token is permitted to access the target endpoint.
	token, ok := c.Get(middleware.TokenContextKey)
	if ok {
		endpointToken := token.(*auth.Token)
		if !endpointToken.EndpointPermitted(endpointID) {
			s.logger.Warn(
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
	}

	s.proxyHandler.ServeHTTP(c.Writer, c.Request, endpointID)
}

func (s *Server) proxyTCPRoute(c *gin.Context) {
	endpointID := c.Param("endpointID")

	token, ok := c.Get(middleware.TokenContextKey)
	if ok {
		endpointToken := token.(*auth.Token)
		if !endpointToken.EndpointPermitted(endpointID) {
			s.logger.Warn(
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
	}

	s.tcpProxy.ServeHTTP(c.Writer, c.Request, endpointID)
}

func (s *Server) panicRoute(c *gin.Context, err any) {
	s.logger.Error(
		"handler panic",
		zap.String("path", c.FullPath()),
		zap.Any("err", err),
	)
	c.AbortWithStatus(http.StatusInternalServerError)
}

func init() {
	gin.SetMode(gin.ReleaseMode)
}

