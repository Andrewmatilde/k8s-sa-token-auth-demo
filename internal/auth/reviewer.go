package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrUnauthenticated means the token was reviewed and rejected. Maps to 401.
	ErrUnauthenticated = errors.New("token not authenticated")
	// ErrReviewUnavailable means the token could not be reviewed (timeout,
	// API server down, ...). Maps to 503; never treated as success, never cached.
	ErrReviewUnavailable = errors.New("token review unavailable")
)

// TokenReviewer verifies a bearer token for the given audience.
// The audience is always server configuration; clients cannot choose it.
// The returned Identity has no Cluster; the Authenticator fills it in.
type TokenReviewer interface {
	Review(ctx context.Context, token string, audience string) (Identity, error)
}

// identityFromReview applies the checks shared by every reviewer to a
// TokenReview status.
func identityFromReview(authenticated bool, statusError, username, uid string, audiences []string, wantAudience string) (Identity, error) {
	if statusError != "" {
		return Identity{}, fmt.Errorf("%w: review status error: %s", ErrUnauthenticated, statusError)
	}
	if !authenticated {
		return Identity{}, fmt.Errorf("%w: not authenticated", ErrUnauthenticated)
	}
	if !slices.Contains(audiences, wantAudience) {
		return Identity{}, fmt.Errorf("%w: audience mismatch", ErrUnauthenticated)
	}
	namespace, name, ok := parseServiceAccountUsername(username)
	if !ok {
		return Identity{}, fmt.Errorf("%w: not a service account identity", ErrUnauthenticated)
	}
	return Identity{Namespace: namespace, ServiceAccount: name, Username: username, UID: uid}, nil
}

// FakeTokenEntry describes what FakeTokenReviewer returns for a known token.
type FakeTokenEntry struct {
	Username  string
	UID       string
	Audiences []string
}

// FakeTokenReviewer is an in-memory TokenReviewer.
//
// DEVELOPMENT AND TESTS ONLY. It trusts a static token table and must never be
// wired into production; cmd/server only enables it behind -dev-fake-reviewer
// and refuses to do so when running inside a Kubernetes Pod.
type FakeTokenReviewer struct {
	mu     sync.RWMutex
	tokens map[string]FakeTokenEntry
	calls  atomic.Int64

	// Delay simulates API server latency; it honours ctx cancellation.
	Delay time.Duration
	// Err, if set, simulates API server failure.
	Err error
}

// NewFakeTokenReviewer returns an empty fake reviewer. Development and tests only.
func NewFakeTokenReviewer() *FakeTokenReviewer {
	return &FakeTokenReviewer{tokens: map[string]FakeTokenEntry{}}
}

// AddToken registers a token.
func (f *FakeTokenReviewer) AddToken(token string, entry FakeTokenEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[token] = entry
}

// Calls returns how many reviews were performed.
func (f *FakeTokenReviewer) Calls() int64 { return f.calls.Load() }

// Review implements TokenReviewer.
func (f *FakeTokenReviewer) Review(ctx context.Context, token, audience string) (Identity, error) {
	f.calls.Add(1)
	if f.Delay > 0 {
		t := time.NewTimer(f.Delay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return Identity{}, fmt.Errorf("%w: %v", ErrReviewUnavailable, ctx.Err())
		case <-t.C:
		}
	}
	if f.Err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrReviewUnavailable, f.Err)
	}
	f.mu.RLock()
	entry, ok := f.tokens[token]
	f.mu.RUnlock()
	if !ok {
		return identityFromReview(false, "", "", "", nil, audience)
	}
	return identityFromReview(true, "", entry.Username, entry.UID, entry.Audiences, audience)
}
