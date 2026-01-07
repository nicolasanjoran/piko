package config

import (
	"fmt"

	"github.com/spf13/pflag"
)

// ACMEConfig configures automatic TLS certificate management via Let's Encrypt.
type ACMEConfig struct {
	// Enabled enables automatic TLS certificate management via ACME/Let's Encrypt.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Email is the contact email for Let's Encrypt notifications.
	// Required when ACME is enabled.
	Email string `json:"email" yaml:"email"`

	// UpstreamDomain is the domain for the upstream server where agents connect.
	// Agents will connect to this domain via WebSocket over HTTPS.
	// Required when ACME is enabled.
	UpstreamDomain string `json:"upstream_domain" yaml:"upstream_domain"`

	// CacheDir is the directory to cache TLS certificates.
	// Defaults to ".piko/certs" if not specified.
	CacheDir string `json:"cache_dir" yaml:"cache_dir"`

	// Staging uses Let's Encrypt staging environment instead of production.
	// Use this for testing to avoid rate limits.
	Staging bool `json:"staging" yaml:"staging"`

	// HTTPChallengePort is the port to listen on for HTTP-01 challenges.
	// Defaults to 80. Let's Encrypt requires port 80 for HTTP-01 challenges.
	HTTPChallengePort int `json:"http_challenge_port" yaml:"http_challenge_port"`
}

func (c *ACMEConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Email == "" {
		return fmt.Errorf("email is required when ACME is enabled")
	}

	if c.UpstreamDomain == "" {
		return fmt.Errorf("upstream_domain is required when ACME is enabled")
	}

	return nil
}

func (c *ACMEConfig) RegisterFlags(fs *pflag.FlagSet) {
	fs.BoolVar(
		&c.Enabled,
		"acme.enabled",
		c.Enabled,
		`
Enable automatic TLS certificate management via ACME/Let's Encrypt.

When enabled, the server will automatically obtain and renew TLS certificates.
Service domains are automatically discovered when agents register them.`,
	)

	fs.StringVar(
		&c.Email,
		"acme.email",
		c.Email,
		`
Contact email address for Let's Encrypt notifications.

Required when ACME is enabled. Let's Encrypt will send expiration warnings
and other important notices to this email.`,
	)

	fs.StringVar(
		&c.UpstreamDomain,
		"acme.upstream-domain",
		c.UpstreamDomain,
		`
Domain for the upstream server where agents connect.

Required when ACME is enabled. Agents will connect to this domain via
WebSocket over HTTPS to register their endpoints.`,
	)

	fs.StringVar(
		&c.CacheDir,
		"acme.cache-dir",
		c.CacheDir,
		`
Directory to cache TLS certificates.

Defaults to ".piko/certs" if not specified.`,
	)

	fs.BoolVar(
		&c.Staging,
		"acme.staging",
		c.Staging,
		`
Use Let's Encrypt staging environment instead of production.

Use this for testing to avoid rate limits. Certificates from staging
are not trusted by browsers.`,
	)

	fs.IntVar(
		&c.HTTPChallengePort,
		"acme.http-challenge-port",
		c.HTTPChallengePort,
		`
Port to listen on for HTTP-01 challenges.

Defaults to 80. Let's Encrypt requires port 80 for HTTP-01 challenges.
You may need to run the server with elevated privileges or use port forwarding.`,
	)
}

// IsUpstreamDomain checks if the given domain is the configured upstream domain.
func (c *ACMEConfig) IsUpstreamDomain(domain string) bool {
	return c.UpstreamDomain != "" && c.UpstreamDomain == domain
}

// IsServiceDomain returns true if the domain is a service domain (not the upstream domain).
// Service domains are discovered dynamically from agent registrations.
func (c *ACMEConfig) IsServiceDomain(domain string) bool {
	return domain != "" && !c.IsUpstreamDomain(domain)
}

