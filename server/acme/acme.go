package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/andydunstall/piko/pkg/log"
	"github.com/andydunstall/piko/server/config"
	"go.uber.org/zap"
)

const (
	// Let's Encrypt production directory URL
	letsEncryptProductionURL = "https://acme-v02.api.letsencrypt.org/directory"
	// Let's Encrypt staging directory URL
	letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Manager handles automatic TLS certificate management via ACME/Let's Encrypt.
type Manager struct {
	certManager *autocert.Manager
	config      config.ACMEConfig
	logger      log.Logger

	// httpServer handles HTTP-01 challenges
	httpServer *http.Server
}

// NewManager creates a new ACME certificate manager.
func NewManager(conf config.ACMEConfig, logger log.Logger) (*Manager, error) {
	logger = logger.WithSubsystem("acme")

	// Ensure cache directory exists
	cacheDir := conf.CacheDir
	if cacheDir == "" {
		cacheDir = ".piko/certs"
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	// Select ACME directory URL
	directoryURL := letsEncryptProductionURL
	if conf.Staging {
		directoryURL = letsEncryptStagingURL
		logger.Info("using Let's Encrypt staging environment")
	}

	// Allow any domain - certificates are obtained on-demand when agents register
	// or when requests come in. ACME will only succeed if the domain points to
	// this server, providing natural validation.
	certManager := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  conf.Email,
		Cache:  autocert.DirCache(cacheDir),
		// No HostPolicy = accept any domain
		Client: &acme.Client{
			DirectoryURL: directoryURL,
		},
	}

	m := &Manager{
		certManager: certManager,
		config:      conf,
		logger:      logger,
	}

	logger.Info(
		"ACME manager initialized",
		zap.String("upstream_domain", conf.UpstreamDomain),
		zap.String("email", conf.Email),
		zap.String("cache_dir", cacheDir),
		zap.Bool("staging", conf.Staging),
	)

	return m, nil
}

// TLSConfig returns a TLS configuration that automatically obtains certificates.
func (m *Manager) TLSConfig() *tls.Config {
	return m.certManager.TLSConfig()
}

// GetCertificate returns a function that can be used as tls.Config.GetCertificate.
// This allows multiple TLS listeners to share the same certificate manager.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.certManager.GetCertificate(hello)
}

// StartHTTPChallengeServer starts the HTTP server for HTTP-01 challenges.
// Let's Encrypt requires port 80 to be accessible for HTTP-01 challenges.
func (m *Manager) StartHTTPChallengeServer() error {
	port := m.config.HTTPChallengePort
	if port == 0 {
		port = 80
	}

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	m.httpServer = &http.Server{
		Handler: m.certManager.HTTPHandler(nil),
	}

	m.logger.Info("starting HTTP challenge server", zap.String("addr", addr))

	go func() {
		if err := m.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			m.logger.Error("HTTP challenge server error", zap.Error(err))
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the ACME manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	if m.httpServer != nil {
		if err := m.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown http challenge server: %w", err)
		}
	}
	return nil
}

// Config returns the ACME configuration.
func (m *Manager) Config() config.ACMEConfig {
	return m.config
}

// CacheDir returns the absolute path to the certificate cache directory.
func (m *Manager) CacheDir() string {
	cacheDir := m.config.CacheDir
	if cacheDir == "" {
		cacheDir = ".piko/certs"
	}
	absPath, err := filepath.Abs(cacheDir)
	if err != nil {
		return cacheDir
	}
	return absPath
}

