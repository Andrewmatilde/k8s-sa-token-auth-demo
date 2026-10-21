package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Job is the demo business object.
type Job struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
}

type jobStore struct {
	mu   sync.Mutex
	jobs []Job
}

// NewDemoHandler wires the demo API:
//
//	GET  /healthz      no auth
//	GET  /api/whoami   authn only
//	GET  /api/jobs     authn + authz
//	POST /api/jobs     authn + authz
func NewDemoHandler(authn *Authenticator, authz Authorizer, logger *slog.Logger) http.Handler {
	store := &jobStore{}

	api := http.NewServeMux()
	api.HandleFunc("GET /api/whoami", func(w http.ResponseWriter, r *http.Request) {
		id, _ := IdentityFrom(r.Context())
		writeJSON(w, http.StatusOK, id)
	})
	api.Handle("GET /api/jobs", RequireAuthorization(authz, logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store.mu.Lock()
		jobs := append([]Job{}, store.jobs...)
		store.mu.Unlock()
		writeJSON(w, http.StatusOK, jobs)
	})))
	api.Handle("POST /api/jobs", RequireAuthorization(authz, logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.Name == "" {
			http.Error(w, "body must be {\"name\": \"...\"}", http.StatusBadRequest)
			return
		}
		id, _ := IdentityFrom(r.Context())
		store.mu.Lock()
		job := Job{ID: len(store.jobs) + 1, Name: in.Name, CreatedBy: id.Namespace + "/" + id.ServiceAccount, CreatedAt: time.Now().UTC()}
		store.jobs = append(store.jobs, job)
		store.mu.Unlock()
		writeJSON(w, http.StatusCreated, job)
	})))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/api/", authn.Middleware(api))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
