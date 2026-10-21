package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	DefaultCacheTTL      = 30 * time.Second
	DefaultReviewTimeout = 3 * time.Second
	defaultMaxEntries    = 10000
	maxTokenLength       = 16 << 10
)

// Config configures an Authenticator. Audience and Cluster are trusted server
// configuration.
type Config struct {
	Reviewer      TokenReviewer
	Audience      string
	Cluster       string
	CacheTTL      time.Duration // default 30s
	ReviewTimeout time.Duration // default 3s
	MaxEntries    int           // default 10000
	Logger        *slog.Logger
	Now           func() time.Time // for tests
}

// Authenticator verifies bearer tokens via TokenReview with a short-TTL
// success-only cache and singleflight de-duplication.
type Authenticator struct {
	reviewer      TokenReviewer
	audience      string
	cluster       string
	ttl           time.Duration
	reviewTimeout time.Duration
	logger        *slog.Logger
	now           func() time.Time
	cache         *authCache
	group         singleflight.Group
}

// NewAuthenticator validates cfg and returns an Authenticator.
func NewAuthenticator(cfg Config) (*Authenticator, error) {
	if cfg.Reviewer == nil {
		return nil, errors.New("auth: reviewer is required")
	}
	if cfg.Audience == "" || cfg.Cluster == "" {
		return nil, errors.New("auth: audience and cluster are required")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	if cfg.ReviewTimeout <= 0 {
		cfg.ReviewTimeout = DefaultReviewTimeout
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = defaultMaxEntries
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Authenticator{
		reviewer:      cfg.Reviewer,
		audience:      cfg.Audience,
		cluster:       cfg.Cluster,
		ttl:           cfg.CacheTTL,
		reviewTimeout: cfg.ReviewTimeout,
		logger:        cfg.Logger,
		now:           cfg.Now,
		cache:         newAuthCache(cfg.MaxEntries, cfg.Now),
	}, nil
}

// Authenticate returns the verified identity for token.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (Identity, error) {
	if token == "" {
		return Identity{}, ErrUnauthenticated
	}
	key := newCacheKey(token, a.audience, a.cluster)
	if e, ok := a.cache.get(key); ok {
		return e.identity, nil
	}
	// Two attempts: a shared singleflight result may already be expired by the
	// time a waiter receives it (e.g. a very slow review with a short TTL).
	for range 2 {
		ch := a.group.DoChan(key.singleflightKey(), func() (any, error) {
			if e, ok := a.cache.get(key); ok {
				return e, nil
			}
			// Detached from the first caller's cancellation so one client
			// disconnecting does not fail every merged waiter; bounded by our own timeout.
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.reviewTimeout)
			defer cancel()
			// TTL counts from before the review, so a slow review never
			// stretches the window in which a revoked token is still accepted.
			reviewedAt := a.now()
			id, err := a.reviewer.Review(rctx, token, a.audience)
			if err != nil {
				return nil, err
			}
			id.Cluster = a.cluster
			e := cacheEntry{identity: id, expiresAt: reviewedAt.Add(a.ttl)}
			a.cache.set(key, e)
			return e, nil
		})
		select {
		case <-ctx.Done():
			return Identity{}, fmt.Errorf("%w: %v", ErrReviewUnavailable, ctx.Err())
		case res := <-ch:
			if res.Err != nil {
				if !errors.Is(res.Err, ErrUnauthenticated) && !errors.Is(res.Err, ErrReviewUnavailable) {
					return Identity{}, fmt.Errorf("%w: %v", ErrReviewUnavailable, res.Err)
				}
				return Identity{}, res.Err
			}
			e := res.Val.(cacheEntry)
			if a.now().Before(e.expiresAt) {
				return e.identity, nil
			}
		}
	}
	return Identity{}, fmt.Errorf("%w: review result expired before use", ErrReviewUnavailable)
}

// Middleware authenticates every request and stores the Identity in the
// request context. It never logs the token.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header)
		if !ok {
			a.logger.Info("authn rejected", "reason", "missing or malformed bearer token", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			writeUnauthorized(w)
			return
		}
		id, err := a.Authenticate(r.Context(), token)
		switch {
		case errors.Is(err, ErrUnauthenticated):
			a.logger.Info("authn rejected", "reason", err.Error(), "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			writeUnauthorized(w)
			return
		case err != nil:
			a.logger.Warn("authn unavailable", "err", err.Error(), "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			http.Error(w, "authentication temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		a.logger.Debug("authn ok", "namespace", id.Namespace, "serviceAccount", id.ServiceAccount, "path", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

// bearerToken accepts exactly one "Authorization: Bearer <jwt-charset token>" header.
func bearerToken(h http.Header) (string, bool) {
	values := h.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > maxTokenLength {
		return "", false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "", false
		}
	}
	return token, true
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="internal-api"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
