package server

import (
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/elematte/observer/internal/autentico"
	"github.com/elematte/observer/internal/config"
	"github.com/elematte/observer/internal/db"
	"github.com/elematte/observer/internal/retention"
	"github.com/elematte/observer/internal/ui"
)

// Server serves both public CSOD webhook ingestion routes and ForwardAuth-protected admin routes.
type Server struct {
	cfg             config.Config
	store           *db.Store
	retention       *retention.Worker
	autenticoClient *autentico.Client
	handler         http.Handler
}

// New constructs the HTTP router and middleware stack.
func New(cfg config.Config, store *db.Store, ret *retention.Worker) *Server {
	s := &Server{
		cfg:       cfg,
		store:     store,
		retention: ret,
		autenticoClient: autentico.NewClient(
			cfg.AutenticoAPIURL,
			cfg.AutenticoAdminClientID,
			cfg.AutenticoAdminClientSecret,
			cfg.AutenticoAdminUsername,
			cfg.AutenticoAdminPassword,
			cfg.AutenticoAdminToken,
		),
	}

	rootMux := http.NewServeMux()

	// Public health check for Docker HEALTHCHECK
	rootMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(r.Context()); err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Public CSOD webhook ingestion route (bypasses Autentico ForwardAuth in Caddy)
	rootMux.HandleFunc("POST /hooks/{slug}", s.handleIngest)
	rootMux.HandleFunc("/hooks/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	})

	// Protected admin API + embedded UI
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /api/me", s.handleMe)
	adminMux.HandleFunc("GET /api/summary", s.handleSummary)
	adminMux.HandleFunc("GET /api/endpoints", s.handleListEndpoints)
	adminMux.HandleFunc("POST /api/endpoints", s.handleCreateEndpoint)
	adminMux.HandleFunc("PUT /api/endpoints/{id}", s.handleUpdateEndpoint)
	adminMux.HandleFunc("DELETE /api/endpoints/{id}", s.handleDeleteEndpoint)
	adminMux.HandleFunc("GET /api/events", s.handleListEvents)
	adminMux.HandleFunc("GET /api/events/{id}", s.handleGetEvent)
	adminMux.HandleFunc("DELETE /api/events/{id}", s.handleDeleteEvent)
	adminMux.HandleFunc("GET /api/audit", s.handleListAuditLogs)
	adminMux.HandleFunc("GET /api/settings", s.handleGetSettings)
	adminMux.HandleFunc("PUT /api/settings", s.handleUpdateSettings)
	adminMux.HandleFunc("POST /api/retention/purge", s.handlePurgeNow)
	adminMux.HandleFunc("POST /api/pgp/generate", s.handleGeneratePGP)

	subFS, _ := fs.Sub(ui.Assets, ".")
	adminMux.Handle("/", http.FileServer(http.FS(subFS)))

	rootMux.Handle("/", s.withForwardAuth(adminMux))
	s.handler = rootMux
	return s
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler {
	return s.handler
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
