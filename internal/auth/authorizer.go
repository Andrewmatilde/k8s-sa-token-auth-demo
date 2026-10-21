package auth

import (
	"log/slog"
	"net/http"
)

// Authorizer decides whether a verified identity may call method+path.
// It only sees the Identity from TokenReview, never client-supplied headers.
type Authorizer interface {
	Authorize(id Identity, method, path string) bool
}

// Rule allows one ServiceAccount to call one method on one exact path.
type Rule struct {
	Namespace      string
	ServiceAccount string
	Method         string
	Path           string
}

// StaticAuthorizer is a default-deny allow list.
type StaticAuthorizer struct {
	allow map[Rule]struct{}
}

// NewStaticAuthorizer builds an allow list from rules; anything else is denied.
func NewStaticAuthorizer(rules ...Rule) *StaticAuthorizer {
	m := make(map[Rule]struct{}, len(rules))
	for _, r := range rules {
		m[r] = struct{}{}
	}
	return &StaticAuthorizer{allow: m}
}

// Authorize implements Authorizer.
func (a *StaticAuthorizer) Authorize(id Identity, method, path string) bool {
	_, ok := a.allow[Rule{Namespace: id.Namespace, ServiceAccount: id.ServiceAccount, Method: method, Path: path}]
	return ok
}

// DemoRules are the example policy:
//
//	production/worker      GET /api/jobs
//	production/controller  GET, POST /api/jobs
func DemoRules() []Rule {
	return []Rule{
		{Namespace: "production", ServiceAccount: "worker", Method: http.MethodGet, Path: "/api/jobs"},
		{Namespace: "production", ServiceAccount: "controller", Method: http.MethodGet, Path: "/api/jobs"},
		{Namespace: "production", ServiceAccount: "controller", Method: http.MethodPost, Path: "/api/jobs"},
	}
}

// RequireAuthorization returns 401 without an identity and 403 when denied.
func RequireAuthorization(authz Authorizer, logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := IdentityFrom(r.Context())
		if !ok {
			writeUnauthorized(w)
			return
		}
		if !authz.Authorize(id, r.Method, r.URL.Path) {
			logger.Info("authz denied", "namespace", id.Namespace, "serviceAccount", id.ServiceAccount, "method", r.Method, "path", r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
