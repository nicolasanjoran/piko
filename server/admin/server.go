package admin

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/atomic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/andydunstall/piko/pkg/auth"
	"github.com/andydunstall/piko/pkg/log"
	"github.com/andydunstall/piko/pkg/middleware"
	"github.com/andydunstall/piko/server/cluster"
	"github.com/andydunstall/piko/server/status"
	"github.com/andydunstall/piko/server/upstream"
)

// Server is the admin HTTP server, which exposes endpoints for metrics, health
// and inspecting the node status.
type Server struct {
	clusterState *cluster.State

	upstreams upstream.Manager

	ready *atomic.Bool

	registry *prometheus.Registry

	proxy *ReverseProxy

	httpServer *http.Server

	router *gin.Engine

	logger log.Logger
}

func NewServer(
	clusterState *cluster.State,
	upstreams upstream.Manager,
	registry *prometheus.Registry,
	verifier *auth.MultiTenantVerifier,
	tlsConfig *tls.Config,
	logger log.Logger,
) *Server {
	logger = logger.WithSubsystem("admin")

	router := gin.New()
	server := &Server{
		clusterState: clusterState,
		upstreams:    upstreams,
		ready:        atomic.NewBool(false),
		registry:     registry,
		proxy:        NewReverseProxy(logger),
		httpServer: &http.Server{
			Handler:   router,
			TLSConfig: tlsConfig,
			ErrorLog:  logger.StdLogger(zapcore.WarnLevel),
		},
		router: router,
		logger: logger,
	}

	// Recover from panics.
	router.Use(gin.CustomRecoveryWithWriter(nil, server.panicRoute))

	if verifier != nil {
		authMiddleware := middleware.NewAuth(verifier, logger)
		router.Use(authMiddleware.Verify)
	}

	if clusterState != nil {
		router.Use(server.forwardInterceptor)
	}

	server.registerRoutes(router)

	return server
}

func (s *Server) Serve(ln net.Listener) error {
	s.logger.Info(
		"starting admin server",
		zap.String("addr", ln.Addr().String()),
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

// Shutdown attempts to gracefully shutdown the server by waiting for pending
// requests to complete.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) AddStatus(route string, handler status.Handler) {
	group := s.router.Group("/status").Group(route)
	handler.Register(group)
}

func (s *Server) SetReady(ready bool) {
	s.ready.Store(ready)
}

func (s *Server) registerRoutes(router *gin.Engine) {
	router.GET("/health", s.healthRoute)
	router.GET("/ready", s.readyRoute)

	// Caddy on-demand TLS endpoint
	// Caddy will call this endpoint to check if a domain is allowed for TLS certificate issuance.
	// According to Caddy's on-demand TLS documentation, it sends a GET request with the domain
	// as a query parameter or in the path. We'll support both formats.
	router.GET("/caddy/check-domain", s.caddyCheckDomainRoute)
	router.GET("/caddy/check-domain/:domain", s.caddyCheckDomainRoute)

	if s.registry != nil {
		router.GET("/metrics", s.metricsHandler())
	}

	// From https://github.com/gin-contrib/pprof/blob/934af36b21728278339704005bcef2eec1375091/pprof.go#L32.
	pprofGroup := s.router.Group("/debug/pprof")
	pprofGroup.GET("/", gin.WrapF(pprof.Index))
	pprofGroup.GET("/cmdline", gin.WrapF(pprof.Cmdline))
	pprofGroup.GET("/profile", gin.WrapF(pprof.Profile))
	pprofGroup.POST("/symbol", gin.WrapF(pprof.Symbol))
	pprofGroup.GET("/symbol", gin.WrapF(pprof.Symbol))
	pprofGroup.GET("/trace", gin.WrapF(pprof.Trace))
	pprofGroup.GET("/allocs", gin.WrapH(pprof.Handler("allocs")))
	pprofGroup.GET("/block", gin.WrapH(pprof.Handler("block")))
	pprofGroup.GET("/goroutine", gin.WrapH(pprof.Handler("goroutine")))
	pprofGroup.GET("/heap", gin.WrapH(pprof.Handler("heap")))
	pprofGroup.GET("/mutex", gin.WrapH(pprof.Handler("mutex")))
	pprofGroup.GET("/threadcreate", gin.WrapH(pprof.Handler("threadcreate")))
}

func (s *Server) healthRoute(c *gin.Context) {
	c.Status(http.StatusOK)
}

func (s *Server) readyRoute(c *gin.Context) {
	if !s.ready.Load() {
		c.Status(http.StatusServiceUnavailable)
		return
	}
	c.Status(http.StatusOK)
}

// caddyCheckDomainRoute handles Caddy's on-demand TLS domain validation requests.
//
// According to Caddy's on-demand TLS documentation, when using the 'ask' directive,
// Caddy will make an HTTP request to the configured URL to check if a domain is allowed.
// The domain can be provided as a query parameter or in the path.
//
// This endpoint returns:
// - 200 OK if the domain is registered as an endpoint (allowed)
// - 403 Forbidden if the domain is not registered (not allowed)
//
// See: https://fivenines.io/blog/caddy-tls-on-demand-complete-guide-to-dynamic-https-with-lets-encrypt/
func (s *Server) caddyCheckDomainRoute(c *gin.Context) {
	// Try to get domain from path parameter first
	domain := c.Param("domain")
	if domain == "" {
		// Fall back to query parameter
		domain = c.Query("domain")
	}
	if domain == "" {
		// Caddy may also send it in the Host header or as a different query param
		domain = c.Query("host")
	}
	if domain == "" {
		// Last resort: use the Host header
		domain = c.Request.Host
	}

	if domain == "" {
		s.logger.Warn("caddy check domain: missing domain parameter")
		c.Status(http.StatusBadRequest)
		return
	}

	// Check if the domain is registered as an endpoint
	if s.upstreams != nil && s.upstreams.HasEndpoint(domain) {
		s.logger.Debug(
			"caddy check domain: allowed",
			zap.String("domain", domain),
		)
		c.Status(http.StatusOK)
		return
	}

	s.logger.Debug(
		"caddy check domain: denied",
		zap.String("domain", domain),
	)
	c.Status(http.StatusForbidden)
}

// forwardInterceptor intercepts all admin requests. If the request has a
// 'forward' query, the request is forwarded to the node with the requested ID.
func (s *Server) forwardInterceptor(c *gin.Context) {
	forward, ok := c.GetQuery("forward")
	if !ok || forward == s.clusterState.LocalID() {
		// No forward configuration so handle locally.
		c.Next()
		return
	}

	node, ok := s.clusterState.Node(forward)
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	ctx := context.WithValue(c.Request.Context(), hostContextKey, node.AdminAddr)
	r := c.Request.WithContext(ctx)

	s.proxy.ServeHTTP(c.Writer, r)

	// Abort to avoid going to the next handler.
	c.Abort()
}

func (s *Server) panicRoute(c *gin.Context, err any) {
	s.logger.Error(
		"handler panic",
		zap.String("path", c.FullPath()),
		zap.Any("err", err),
	)
	c.AbortWithStatus(http.StatusInternalServerError)
}

func (s *Server) metricsHandler() gin.HandlerFunc {
	h := promhttp.HandlerFor(
		s.registry,
		promhttp.HandlerOpts{Registry: s.registry},
	)
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func init() {
	// Disable Gin debug logs.
	gin.SetMode(gin.ReleaseMode)
}
