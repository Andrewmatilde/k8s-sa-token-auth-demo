// Command client calls the demo internal API with a projected SA token.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"satokenauth/internal/auth"
)

func main() {
	var (
		tokenFile = flag.String("token-file", auth.DefaultTokenFile, "projected ServiceAccount token file")
		caFile    = flag.String("ca-file", "", "CA bundle that signed the server certificate (empty = system roots)")
		target    = flag.String("url", "https://localhost:8443/api/whoami", "URL to call")
		method    = flag.String("method", http.MethodGet, "HTTP method")
		body      = flag.String("data", "", "request body (JSON)")
		interval  = flag.Duration("interval", 0, "repeat every interval (0 = once)")
		demo      = flag.Bool("demo", false, "treat -url as the API base URL and call whoami, GET /api/jobs and POST /api/jobs")
	)
	flag.Parse()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	u, err := url.Parse(*target)
	if err != nil {
		logger.Error("bad url", "err", err.Error())
		os.Exit(2)
	}
	// Only the target API host may ever receive the token.
	client, err := auth.NewClient(auth.WithTokenFile(*tokenFile), auth.WithCAFile(*caFile), auth.WithAllowedHosts(u.Hostname()))
	if err != nil {
		logger.Error("build client", "err", err.Error())
		os.Exit(2)
	}
	type request struct{ method, url, body string }
	reqs := []request{{*method, *target, *body}}
	if *demo {
		base := strings.TrimSuffix(*target, "/")
		reqs = []request{
			{http.MethodGet, base + "/api/whoami", ""},
			{http.MethodGet, base + "/api/jobs", ""},
			{http.MethodPost, base + "/api/jobs", `{"name":"demo"}`},
		}
	}
	for {
		for _, r := range reqs {
			if err := call(client, r.method, r.url, r.body); err != nil {
				logger.Error("request failed", "err", err.Error())
				if *interval == 0 {
					os.Exit(1)
				}
			}
		}
		if *interval == 0 {
			return
		}
		time.Sleep(*interval)
	}
}

func call(client *http.Client, method, target, body string) error {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		return err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	fmt.Printf("%s %s -> %d %s\n", method, target, resp.StatusCode, strings.TrimSpace(string(out)))
	return nil
}
