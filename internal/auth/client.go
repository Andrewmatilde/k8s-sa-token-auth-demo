package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultTokenFile is where deploy/kubernetes mounts the projected token.
const DefaultTokenFile = "/var/run/secrets/internal-api/token"

type clientConfig struct {
	tokenFile    string
	caFile       string
	allowedHosts map[string]bool
	timeout      time.Duration
}

// ClientOption configures NewClient.
type ClientOption func(*clientConfig)

// WithTokenFile sets the projected ServiceAccount token path.
func WithTokenFile(path string) ClientOption { return func(c *clientConfig) { c.tokenFile = path } }

// WithCAFile trusts the PEM CA bundle at path instead of the system roots.
func WithCAFile(path string) ClientOption { return func(c *clientConfig) { c.caFile = path } }

// WithAllowedHosts restricts which hostnames receive the token.
func WithAllowedHosts(hosts ...string) ClientOption {
	return func(c *clientConfig) {
		for _, h := range hosts {
			c.allowedHosts[strings.ToLower(h)] = true
		}
	}
}

// WithTimeout sets the overall request timeout (default 10s).
func WithTimeout(d time.Duration) ClientOption { return func(c *clientConfig) { c.timeout = d } }

// NewClient returns an *http.Client that injects the ServiceAccount token.
//
// The token file is re-read on every request so kubelet rotation (atomic
// ..data symlink swap) is picked up; nothing is cached. The token is only sent
// over HTTPS with verified server certificates, only to allowed hosts (if
// configured), and cross-host redirects are refused.
func NewClient(opts ...ClientOption) (*http.Client, error) {
	cfg := clientConfig{tokenFile: DefaultTokenFile, allowedHosts: map[string]bool{}, timeout: 10 * time.Second}
	for _, o := range opts {
		o(&cfg)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.caFile != "" {
		pem, err := os.ReadFile(cfg.caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no PEM certificates")
		}
		tlsCfg.RootCAs = pool
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = tlsCfg
	return &http.Client{
		Timeout:   cfg.timeout,
		Transport: &tokenTransport{base: base, tokenFile: cfg.tokenFile, allowedHosts: cfg.allowedHosts},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Host != via[0].URL.Host || req.URL.Scheme != "https" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, nil
}

type tokenTransport struct {
	base         http.RoundTripper
	tokenFile    string
	allowedHosts map[string]bool
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("refusing to send service account token over %q", req.URL.Scheme)
	}
	if len(t.allowedHosts) > 0 && !t.allowedHosts[strings.ToLower(req.URL.Hostname())] {
		return nil, fmt.Errorf("refusing to send service account token to host %q", req.URL.Hostname())
	}
	raw, err := os.ReadFile(t.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil, errors.New("token file is empty")
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(r)
}
