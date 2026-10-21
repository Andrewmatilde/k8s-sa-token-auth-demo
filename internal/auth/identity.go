package auth

import (
	"context"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Identity is a ServiceAccount identity verified by TokenReview.
// Cluster always comes from trusted server configuration, never from the request.
type Identity struct {
	Cluster        string `json:"cluster"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	Username       string `json:"username"`
	UID            string `json:"uid"`
}

type identityKey struct{}

// WithIdentity returns a copy of ctx carrying id.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the authenticated identity stored by the middleware.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

const serviceAccountPrefix = "system:serviceaccount:"

// parseServiceAccountUsername accepts only "system:serviceaccount:<namespace>:<name>".
func parseServiceAccountUsername(username string) (namespace, name string, ok bool) {
	rest, found := strings.CutPrefix(username, serviceAccountPrefix)
	if !found {
		return "", "", false
	}
	namespace, name, found = strings.Cut(rest, ":")
	if !found {
		return "", "", false
	}
	if len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(name)) != 0 {
		return "", "", false
	}
	return namespace, name, true
}
