// Command server is the demo internal API server.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"satokenauth/internal/auth"
)

func main() {
	var (
		addr          = flag.String("addr", ":8443", "HTTPS listen address")
		certFile      = flag.String("tls-cert", "", "server certificate (PEM), required")
		keyFile       = flag.String("tls-key", "", "server private key (PEM), required")
		audience      = flag.String("audience", "internal-api", "expected token audience")
		cluster       = flag.String("cluster", "", "trusted cluster identifier, required")
		kubeconfig    = flag.String("kubeconfig", "", "kubeconfig for TokenReview (empty = in-cluster)")
		cacheTTL      = flag.Duration("cache-ttl", auth.DefaultCacheTTL, "successful authentication cache TTL")
		reviewTimeout = flag.Duration("review-timeout", auth.DefaultReviewTimeout, "TokenReview timeout")
		fakeReviewer  = flag.Bool("dev-fake-reviewer", false, "DEVELOPMENT ONLY: use the in-memory fake TokenReviewer with demo tokens")
		debug         = flag.Bool("debug", false, "debug logging")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := run(logger, *addr, *certFile, *keyFile, *audience, *cluster, *kubeconfig, *cacheTTL, *reviewTimeout, *fakeReviewer); err != nil {
		logger.Error("server exited", "err", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger, addr, certFile, keyFile, audience, cluster, kubeconfig string, cacheTTL, reviewTimeout time.Duration, fake bool) error {
	if certFile == "" || keyFile == "" {
		return errors.New("-tls-cert and -tls-key are required (plain HTTP is not supported)")
	}
	if cluster == "" {
		return errors.New("-cluster is required")
	}

	var reviewer auth.TokenReviewer
	if fake {
		// Guard against accidentally shipping fake mode: refuse inside a Pod.
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			return errors.New("-dev-fake-reviewer is not allowed when running inside Kubernetes")
		}
		logger.Warn("USING FAKE TOKEN REVIEWER: development only, demo tokens are accepted without Kubernetes")
		reviewer = demoFakeReviewer(audience)
	} else {
		cfg, err := auth.LoadRESTConfig(kubeconfig)
		if err != nil {
			return err
		}
		cfg.Timeout = reviewTimeout
		kr, err := auth.NewKubernetesTokenReviewer(cfg)
		if err != nil {
			return err
		}
		reviewer = kr
	}

	authn, err := auth.NewAuthenticator(auth.Config{
		Reviewer: reviewer, Audience: audience, Cluster: cluster,
		CacheTTL: cacheTTL, ReviewTimeout: reviewTimeout, Logger: logger,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           auth.NewDemoHandler(authn, auth.NewStaticAuthorizer(auth.DemoRules()...), logger),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	logger.Info("listening", "addr", addr, "audience", audience, "cluster", cluster, "fakeReviewer", fake)
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// demoFakeReviewer seeds fixed demo tokens. Development only.
func demoFakeReviewer(audience string) *auth.FakeTokenReviewer {
	f := auth.NewFakeTokenReviewer()
	f.AddToken("dev-worker-token", auth.FakeTokenEntry{Username: "system:serviceaccount:production:worker", UID: "uid-worker", Audiences: []string{audience}})
	f.AddToken("dev-controller-token", auth.FakeTokenEntry{Username: "system:serviceaccount:production:controller", UID: "uid-controller", Audiences: []string{audience}})
	f.AddToken("dev-other-token", auth.FakeTokenEntry{Username: "system:serviceaccount:default:other", UID: "uid-other", Audiences: []string{audience}})
	f.AddToken("dev-wrong-audience-token", auth.FakeTokenEntry{Username: "system:serviceaccount:production:worker", UID: "uid-worker", Audiences: []string{"https://kubernetes.default.svc"}})
	return f
}
