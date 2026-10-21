package auth

import (
	"context"
	"fmt"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesTokenReviewer calls authentication.k8s.io/v1 TokenReview on a
// trusted API server (in-cluster config or an explicit kubeconfig).
type KubernetesTokenReviewer struct {
	client kubernetes.Interface
}

// NewKubernetesTokenReviewer builds a reviewer from rest config.
func NewKubernetesTokenReviewer(cfg *rest.Config) (*KubernetesTokenReviewer, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	return &KubernetesTokenReviewer{client: cs}, nil
}

// LoadRESTConfig uses kubeconfig when given, otherwise in-cluster config.
func LoadRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig: %w", err)
		}
		return cfg, nil
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config: %w", err)
	}
	return cfg, nil
}

// Review implements TokenReviewer. ctx carries the timeout/cancellation.
func (r *KubernetesTokenReviewer) Review(ctx context.Context, token, audience string) (Identity, error) {
	req := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{audience}},
	}
	// client-go v0.18 is the first release whose typed clients take a context.
	res, err := r.client.AuthenticationV1().TokenReviews().Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		// Never fail open: any transport/API error is "unavailable".
		return Identity{}, fmt.Errorf("%w: %v", ErrReviewUnavailable, err)
	}
	st := res.Status
	return identityFromReview(st.Authenticated, st.Error, st.User.Username, st.User.UID, st.Audiences, audience)
}
