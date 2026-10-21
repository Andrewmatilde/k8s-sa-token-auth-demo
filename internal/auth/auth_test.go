package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/client-go/rest"
)

const (
	testAudience = "internal-api"
	testCluster  = "uk8s-test"

	workerToken     = "worker.jwt.token"
	controllerToken = "controller.jwt.token"
	otherToken      = "other.jwt.token"
	wrongAudToken   = "wrongaud.jwt.token"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

func newFake() *FakeTokenReviewer {
	f := NewFakeTokenReviewer()
	f.AddToken(workerToken, FakeTokenEntry{Username: "system:serviceaccount:production:worker", UID: "u-worker", Audiences: []string{testAudience}})
	f.AddToken(controllerToken, FakeTokenEntry{Username: "system:serviceaccount:production:controller", UID: "u-controller", Audiences: []string{testAudience}})
	f.AddToken(otherToken, FakeTokenEntry{Username: "system:serviceaccount:default:other", UID: "u-other", Audiences: []string{testAudience}})
	f.AddToken(wrongAudToken, FakeTokenEntry{Username: "system:serviceaccount:production:worker", UID: "u-worker", Audiences: []string{"https://kubernetes.default.svc"}})
	return f
}

type env struct {
	reviewer *FakeTokenReviewer
	authn    *Authenticator
	clock    *fakeClock
	handler  http.Handler
	logs     *bytes.Buffer
}

func newEnv(t testing.TB, reviewer TokenReviewer, mutate func(*Config)) *env {
	t.Helper()
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(&lockedWriter{w: logs}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := Config{Reviewer: reviewer, Audience: testAudience, Cluster: testCluster, Logger: logger, Now: clock.Now}
	if mutate != nil {
		mutate(&cfg)
	}
	authn, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fake, _ := reviewer.(*FakeTokenReviewer)
	return &env{
		reviewer: fake, authn: authn, clock: clock, logs: logs,
		handler: NewDemoHandler(authn, NewStaticAuthorizer(DemoRules()...), logger),
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (e *env) do(method, path, token string) *httptest.ResponseRecorder {
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"name":"j1"}`)
	}
	req := httptest.NewRequest(method, path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// 1. valid token
func TestValidTokenAuthenticates(t *testing.T) {
	e := newEnv(t, newFake(), nil)
	rec := e.do(http.MethodGet, "/api/whoami", workerToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var id Identity
	if err := json.Unmarshal(rec.Body.Bytes(), &id); err != nil {
		t.Fatal(err)
	}
	want := Identity{Cluster: testCluster, Namespace: "production", ServiceAccount: "worker", Username: "system:serviceaccount:production:worker", UID: "u-worker"}
	if id != want {
		t.Fatalf("identity = %+v, want %+v", id, want)
	}
	if strings.Contains(rec.Body.String(), workerToken) {
		t.Fatal("whoami leaked the token")
	}
}

func TestHealthzNoAuth(t *testing.T) {
	e := newEnv(t, newFake(), nil)
	if rec := e.do(http.MethodGet, "/healthz", ""); rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
	if e.reviewer.Calls() != 0 {
		t.Fatal("healthz triggered TokenReview")
	}
}

// 2 + 3. missing / malformed / wrong tokens
func TestUnauthenticatedReturns401(t *testing.T) {
	e := newEnv(t, newFake(), nil)
	cases := map[string]func(*http.Request){
		"no header":    func(*http.Request) {},
		"basic scheme": func(r *http.Request) { r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") },
		"empty bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"bad charset":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer a b") },
		"two headers": func(r *http.Request) {
			r.Header.Add("Authorization", "Bearer "+workerToken)
			r.Header.Add("Authorization", "Bearer x")
		},
		"unknown token": func(r *http.Request) { r.Header.Set("Authorization", "Bearer not.a.valid.token") },
		"spoofed headers only": func(r *http.Request) {
			r.Header.Set("X-Namespace", "production")
			r.Header.Set("X-Service-Account", "controller")
			r.Header.Set("X-Cluster", testCluster)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/jobs", nil)
			mutate(req)
			rec := httptest.NewRecorder()
			e.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if rec.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing WWW-Authenticate")
			}
		})
	}
}

// 4. audience mismatch
func TestAudienceMismatchReturns401(t *testing.T) {
	e := newEnv(t, newFake(), nil)
	if rec := e.do(http.MethodGet, "/api/whoami", wrongAudToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestNonServiceAccountUserRejected(t *testing.T) {
	f := newFake()
	f.AddToken("user.token", FakeTokenEntry{Username: "kubernetes-admin", Audiences: []string{testAudience}})
	f.AddToken("bad.sa.token", FakeTokenEntry{Username: "system:serviceaccount:production:worker:extra", Audiences: []string{testAudience}})
	e := newEnv(t, f, nil)
	for _, tok := range []string{"user.token", "bad.sa.token"} {
		if rec := e.do(http.MethodGet, "/api/whoami", tok); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", tok, rec.Code)
		}
	}
}

// 5. authorization
func TestAuthorizationMatrix(t *testing.T) {
	e := newEnv(t, newFake(), nil)
	cases := []struct {
		token, method string
		want          int
	}{
		{workerToken, http.MethodGet, http.StatusOK},
		{workerToken, http.MethodPost, http.StatusForbidden},
		{controllerToken, http.MethodGet, http.StatusOK},
		{controllerToken, http.MethodPost, http.StatusCreated},
		{otherToken, http.MethodGet, http.StatusForbidden},
		{otherToken, http.MethodPost, http.StatusForbidden},
	}
	for _, c := range cases {
		if rec := e.do(c.method, "/api/jobs", c.token); rec.Code != c.want {
			t.Errorf("%s %s: status = %d, want %d", c.token, c.method, rec.Code, c.want)
		}
	}
}

// 6. cache hit
func TestCacheHitSkipsTokenReview(t *testing.T) {
	e := newEnv(t, newFake(), nil)
	for range 10 {
		if rec := e.do(http.MethodGet, "/api/whoami", workerToken); rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		e.clock.Advance(time.Second)
	}
	if got := e.reviewer.Calls(); got != 1 {
		t.Fatalf("TokenReview calls = %d, want 1", got)
	}
}

// 7. cache expiry
func TestCacheExpiryReReviews(t *testing.T) {
	e := newEnv(t, newFake(), func(c *Config) { c.CacheTTL = 30 * time.Second })
	e.do(http.MethodGet, "/api/whoami", workerToken)
	e.clock.Advance(29 * time.Second)
	e.do(http.MethodGet, "/api/whoami", workerToken)
	if got := e.reviewer.Calls(); got != 1 {
		t.Fatalf("calls before expiry = %d, want 1", got)
	}
	e.clock.Advance(time.Second) // exactly at expiry: must not be used
	e.do(http.MethodGet, "/api/whoami", workerToken)
	if got := e.reviewer.Calls(); got != 2 {
		t.Fatalf("calls after expiry = %d, want 2", got)
	}
}

func TestRevokedTokenRejectedAfterTTL(t *testing.T) {
	f := newFake()
	e := newEnv(t, f, nil)
	e.do(http.MethodGet, "/api/whoami", workerToken)
	f.mu.Lock()
	delete(f.tokens, workerToken) // simulate deletion of the SA / pod
	f.mu.Unlock()
	if rec := e.do(http.MethodGet, "/api/whoami", workerToken); rec.Code != http.StatusOK {
		t.Fatalf("within TTL: %d, want 200 (documented revocation delay)", rec.Code)
	}
	e.clock.Advance(DefaultCacheTTL)
	if rec := e.do(http.MethodGet, "/api/whoami", workerToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after TTL: %d, want 401", rec.Code)
	}
}

// 8. singleflight
func TestConcurrentSameTokenSingleflight(t *testing.T) {
	f := newFake()
	f.Delay = 100 * time.Millisecond
	e := newEnv(t, f, nil)
	const n = 100
	var wg sync.WaitGroup
	var ok atomic.Int64
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if rec := e.do(http.MethodGet, "/api/whoami", workerToken); rec.Code == http.StatusOK {
				ok.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != n {
		t.Fatalf("successful = %d, want %d", ok.Load(), n)
	}
	if got := f.Calls(); got != 1 {
		t.Fatalf("TokenReview calls = %d, want 1", got)
	}
}

func TestSingleflightResultExpiredIsNotReused(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	r := &advancingReviewer{inner: newFake(), clock: clock, advance: time.Minute}
	a, err := NewAuthenticator(Config{Reviewer: r, Audience: testAudience, Cluster: testCluster, CacheTTL: 30 * time.Second, Now: clock.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	// Each review "takes" longer than the TTL, so every result is already expired.
	if _, err := a.Authenticate(context.Background(), workerToken); !errors.Is(err, ErrReviewUnavailable) {
		t.Fatalf("err = %v, want ErrReviewUnavailable", err)
	}
}

// advancingReviewer moves the clock forward during a review, like a slow API server.
type advancingReviewer struct {
	inner   TokenReviewer
	clock   *fakeClock
	advance time.Duration
}

func (r *advancingReviewer) Review(ctx context.Context, token, aud string) (Identity, error) {
	id, err := r.inner.Review(ctx, token, aud)
	r.clock.Advance(r.advance)
	return id, err
}

// 9. fail closed
func TestTokenReviewTimeoutFailsClosed(t *testing.T) {
	f := newFake()
	f.Delay = 2 * time.Second
	e := newEnv(t, f, func(c *Config) { c.ReviewTimeout = 50 * time.Millisecond })
	startAt := time.Now()
	rec := e.do(http.MethodGet, "/api/whoami", workerToken)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if time.Since(startAt) > time.Second {
		t.Fatal("timeout was not enforced")
	}
	f.Delay = 0
	e.do(http.MethodGet, "/api/whoami", workerToken)
	if got := f.Calls(); got != 2 {
		t.Fatalf("calls = %d, want 2 (failure must not be cached)", got)
	}
}

func TestAPIServerUnavailableFailsClosed(t *testing.T) {
	f := newFake()
	f.Err = errors.New("connection refused")
	e := newEnv(t, f, nil)
	for range 3 {
		if rec := e.do(http.MethodGet, "/api/jobs", workerToken); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	}
	if got := f.Calls(); got != 3 {
		t.Fatalf("calls = %d, want 3 (errors must not be cached)", got)
	}
}

// 10. token never logged
func TestTokenNotLogged(t *testing.T) {
	f := newFake()
	e := newEnv(t, f, nil)
	e.do(http.MethodGet, "/api/whoami", workerToken)
	e.do(http.MethodPost, "/api/jobs", workerToken)
	e.do(http.MethodGet, "/api/jobs", "unknown.secret.value")
	e.do(http.MethodGet, "/api/jobs", wrongAudToken)
	f.Err = errors.New("boom")
	e.do(http.MethodGet, "/api/jobs", controllerToken)
	logs := e.logs.String()
	if logs == "" {
		t.Fatal("expected some logs")
	}
	for _, tok := range []string{workerToken, "unknown.secret.value", wrongAudToken, controllerToken} {
		if strings.Contains(logs, tok) {
			t.Fatalf("log contains token %q:\n%s", tok, logs)
		}
	}
}

// 12. different tokens do not share cache
func TestDifferentTokensDoNotShareCache(t *testing.T) {
	e := newEnv(t, newFake(), nil)
	var a, b Identity
	_ = json.Unmarshal(e.do(http.MethodGet, "/api/whoami", workerToken).Body.Bytes(), &a)
	_ = json.Unmarshal(e.do(http.MethodGet, "/api/whoami", controllerToken).Body.Bytes(), &b)
	if a.ServiceAccount != "worker" || b.ServiceAccount != "controller" {
		t.Fatalf("got %q and %q", a.ServiceAccount, b.ServiceAccount)
	}
	if rec := e.do(http.MethodGet, "/api/whoami", workerToken+"x"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("similar token status = %d, want 401", rec.Code)
	}
	if got := e.reviewer.Calls(); got != 3 {
		t.Fatalf("calls = %d, want 3", got)
	}
}

func TestCacheKeyIncludesAudienceAndCluster(t *testing.T) {
	base := newCacheKey(workerToken, testAudience, testCluster)
	if base == newCacheKey(workerToken, "other", testCluster) || base == newCacheKey(workerToken, testAudience, "other") {
		t.Fatal("cache key must include audience and cluster")
	}
	if strings.Contains(fmt.Sprintf("%v", base), workerToken) {
		t.Fatal("cache key contains plaintext token")
	}
}

// 11. client token rotation, TLS verification and token scoping
func TestClientPicksUpRotatedToken(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer srv.Close()
	caFile := writeCA(t, srv)

	// Mimic kubelet's atomic writer: token -> ..data/token, ..data -> ..<ts>/
	dir := t.TempDir()
	writeVersion := func(name, token string) {
		vdir := filepath.Join(dir, name)
		if err := os.Mkdir(vdir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vdir, "token"), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		tmp := filepath.Join(dir, "..data_tmp")
		if err := os.Symlink(name, tmp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	writeVersion("..v1", "token.one")
	if err := os.Symlink(filepath.Join("..data", "token"), filepath.Join(dir, "token")); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(WithTokenFile(filepath.Join(dir, "token")), WithCAFile(caFile), WithAllowedHosts("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	get := func() {
		resp, err := client.Get(srv.URL + "/api/jobs")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	get()
	writeVersion("..v2", "token.two")
	get()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "Bearer token.one" || seen[1] != "Bearer token.two" {
		t.Fatalf("seen = %v", seen)
	}
}

func TestClientRefusesUnsafeDestinations(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tokenFile, []byte("secret.token"), 0o600)

	// Untrusted cert: TLS verification must fail.
	noCA, err := NewClient(WithTokenFile(tokenFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noCA.Get(srv.URL); err == nil {
		t.Fatal("expected certificate verification error")
	}

	client, err := NewClient(WithTokenFile(tokenFile), WithCAFile(writeCA(t, srv)), WithAllowedHosts("internal-api.example"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected host refusal, got %v", err)
	}
	if _, err := client.Get("http://internal-api.example/"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected scheme refusal, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("server should never have received a request")
	}
}

func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// KubernetesTokenReviewer against a fake authentication.k8s.io/v1 endpoint,
// exercising the real client-go v0.18 code path.
func TestKubernetesTokenReviewer(t *testing.T) {
	var delay atomic.Int64
	var fail atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer server-sa-credential" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if d := time.Duration(delay.Load()); d > 0 {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
				return
			}
		}
		if fail.Load() {
			http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":500}`, http.StatusInternalServerError)
			return
		}
		var tr authnv1.TokenReview
		if err := json.NewDecoder(r.Body).Decode(&tr); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tr.APIVersion, tr.Kind = "authentication.k8s.io/v1", "TokenReview"
		switch tr.Spec.Token {
		case workerToken:
			// Like kube-apiserver 1.17/1.18: returns the intersection of requested
			// and token audiences.
			if len(tr.Spec.Audiences) == 1 && tr.Spec.Audiences[0] == testAudience {
				tr.Status = authnv1.TokenReviewStatus{Authenticated: true, Audiences: []string{testAudience},
					User: authnv1.UserInfo{Username: "system:serviceaccount:production:worker", UID: "u-worker"}}
			} else {
				tr.Status = authnv1.TokenReviewStatus{Error: "token audiences is invalid for the target audiences"}
			}
		case "noaud.token":
			tr.Status = authnv1.TokenReviewStatus{Authenticated: true, User: authnv1.UserInfo{Username: "system:serviceaccount:production:worker"}}
		default:
			tr.Status = authnv1.TokenReviewStatus{Error: "invalid bearer token"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&tr)
	}))
	defer srv.Close()

	cfg := &rest.Config{
		Host:            srv.URL,
		BearerToken:     "server-sa-credential",
		TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})},
	}
	kr, err := NewKubernetesTokenReviewer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	id, err := kr.Review(ctx, workerToken, testAudience)
	if err != nil || id.Namespace != "production" || id.ServiceAccount != "worker" || id.UID != "u-worker" {
		t.Fatalf("valid: id=%+v err=%v", id, err)
	}
	if _, err := kr.Review(ctx, workerToken, "other-audience"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong audience: err=%v", err)
	}
	if _, err := kr.Review(ctx, "noaud.token", testAudience); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("missing status.audiences: err=%v", err)
	}
	if _, err := kr.Review(ctx, "garbage", testAudience); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("invalid token: err=%v", err)
	}

	fail.Store(true)
	if _, err := kr.Review(ctx, workerToken, testAudience); !errors.Is(err, ErrReviewUnavailable) {
		t.Fatalf("500: err=%v", err)
	}
	fail.Store(false)

	delay.Store(int64(300 * time.Millisecond))
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := kr.Review(tctx, workerToken, testAudience); !errors.Is(err, ErrReviewUnavailable) {
		t.Fatalf("timeout: err=%v", err)
	}
	delay.Store(0)

	srv.Close()
	if _, err := kr.Review(ctx, workerToken, testAudience); !errors.Is(err, ErrReviewUnavailable) {
		t.Fatalf("server down: err=%v", err)
	}
}

func BenchmarkAuthCacheHit(b *testing.B) {
	e := newEnv(b, newFake(), func(c *Config) { c.Now = time.Now })
	ctx := context.Background()
	if _, err := e.authn.Authenticate(ctx, workerToken); err != nil {
		b.Fatal(err)
	}
	before := e.reviewer.Calls()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.authn.Authenticate(ctx, workerToken); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(e.reviewer.Calls()-before), "tokenreviews")
}

func BenchmarkAuthCacheMiss(b *testing.B) {
	f := newFake()
	tokens := make([]string, b.N)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("miss.token.%d", i)
		f.AddToken(tokens[i], FakeTokenEntry{Username: "system:serviceaccount:production:worker", Audiences: []string{testAudience}})
	}
	e := newEnv(b, f, func(c *Config) { c.Now = time.Now; c.MaxEntries = b.N + 1 })
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.authn.Authenticate(ctx, tokens[i]); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(f.Calls())/float64(b.N), "tokenreviews/op")
}

func BenchmarkConcurrentAuth(b *testing.B) {
	f := newFake()
	f.Delay = time.Millisecond // a realistic-ish review latency for the cold start
	e := newEnv(b, f, func(c *Config) { c.Now = time.Now })
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := e.authn.Authenticate(ctx, workerToken); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(f.Calls()), "tokenreviews")
}
