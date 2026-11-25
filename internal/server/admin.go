package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/elematte/observer/internal/csod"
	"github.com/elematte/observer/internal/db"
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func (s *Server) withForwardAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.TrustForwardAuth {
			uid := strings.TrimSpace(r.Header.Get("X-Auth-User"))
			email := strings.TrimSpace(r.Header.Get("X-Auth-Email"))
			if uid == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing Autentico ForwardAuth identity")
				return
			}
			if len(s.cfg.AllowedUsers) > 0 {
				_, okID := s.cfg.AllowedUsers[strings.ToLower(uid)]
				_, okEmail := s.cfg.AllowedUsers[strings.ToLower(email)]
				if !okID && (email == "" || !okEmail) {
					writeJSONError(w, http.StatusForbidden, "user is not in OBSERVER_ALLOWED_USERS")
					return
				}
			}
		}

		if isMutatingMethod(r.Method) {
			if err := verifyCSRF(r); err != nil {
				writeJSONError(w, http.StatusForbidden, err.Error())
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func verifyCSRF(r *http.Request) error {
	if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-Requested-With") == "" {
		return errors.New("missing X-Requested-With header")
	}

	reqHost := requestHost(r)
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, reqHost) {
			return errors.New("origin mismatch")
		}
		return nil
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
		u, err := url.Parse(referer)
		if err != nil || !strings.EqualFold(u.Host, reqHost) {
			return errors.New("referer mismatch")
		}
	}
	return nil
}

func requestHost(r *http.Request) string {
	if xfHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xfHost != "" {
		if idx := strings.IndexByte(xfHost, ','); idx >= 0 {
			xfHost = strings.TrimSpace(xfHost[:idx])
		}
		return xfHost
	}
	return r.Host
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	uid := strings.TrimSpace(r.Header.Get("X-Auth-User"))
	if uid == "" && !s.cfg.TrustForwardAuth {
		uid = "local-dev"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"userId":           uid,
		"email":            strings.TrimSpace(r.Header.Get("X-Auth-Email")),
		"forwardAuthTrust": s.cfg.TrustForwardAuth,
		"logoutPath":       s.cfg.AutenticoLogoutPath,
	})
}

func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
	eps, err := s.store.ListEndpoints(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if eps == nil {
		eps = []db.Endpoint{}
	}
	writeJSON(w, http.StatusOK, eps)
}

type endpointRequest struct {
	Name                   string            `json:"name"`
	Slug                   string            `json:"slug"`
	Enabled                bool              `json:"enabled"`
	APIKey                 *string           `json:"apiKey"`
	ClearAPIKey            bool              `json:"clearApiKey"`
	HMACSecret             *string           `json:"hmacSecret"`
	ClearHMACSecret        bool              `json:"clearHmacSecret"`
	HMACRequired           bool              `json:"hmacRequired"`
	CustomHeaders          map[string]string `json:"customHeaders"`
	PGPPrivateKey          *string           `json:"pgpPrivateKey"`
	ClearPGPPrivateKey     bool              `json:"clearPgpPrivateKey"`
	PGPPassphrase          *string           `json:"pgpPassphrase"`
	ClearPGPPassphrase     bool              `json:"clearPgpPassphrase"`
	RetentionDays          *int              `json:"retentionDays"`
	HeartbeatRetentionDays *int              `json:"heartbeatRetentionDays"`
	StoreRawOnError        bool              `json:"storeRawOnError"`
}

func (req *endpointRequest) validate() error {
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if req.Name == "" {
		return errors.New("name is required")
	}
	if !slugRe.MatchString(req.Slug) {
		return errors.New("slug must match ^[a-z0-9][a-z0-9_-]{0,63}$")
	}
	if err := csod.ValidateCustomHeadersConfig(req.CustomHeaders); err != nil {
		return err
	}
	if req.RetentionDays != nil && *req.RetentionDays < 1 {
		return errors.New("retentionDays must be >= 1")
	}
	if req.HeartbeatRetentionDays != nil && *req.HeartbeatRetentionDays < 1 {
		return errors.New("heartbeatRetentionDays must be >= 1")
	}
	if req.PGPPrivateKey != nil && strings.TrimSpace(*req.PGPPrivateKey) != "" {
		if _, err := openpgp.ReadArmoredKeyRing(strings.NewReader(*req.PGPPrivateKey)); err != nil {
			return errors.New("pgpPrivateKey must be a valid ASCII-armored OpenPGP key block")
		}
	}
	return nil
}

func (s *Server) handleCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	var req endpointRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := req.validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	ep := db.Endpoint{
		Name:                   req.Name,
		Slug:                   req.Slug,
		Enabled:                req.Enabled,
		APIKey:                 derefTrim(req.APIKey),
		HMACSecret:             derefTrim(req.HMACSecret),
		HMACRequired:           req.HMACRequired,
		CustomHeaders:          req.CustomHeaders,
		PGPPrivateKey:          derefStr(req.PGPPrivateKey),
		PGPPassphrase:          derefStr(req.PGPPassphrase),
		RetentionDays:          req.RetentionDays,
		HeartbeatRetentionDays: req.HeartbeatRetentionDays,
		StoreRawOnError:        req.StoreRawOnError,
	}

	created, err := s.store.CreateEndpoint(r.Context(), ep)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSONError(w, http.StatusConflict, "an endpoint with this slug already exists")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid endpoint id")
		return
	}

	var req endpointRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := req.validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := s.store.UpdateEndpoint(r.Context(), id, db.EndpointPatch{
		Name:                   req.Name,
		Slug:                   req.Slug,
		Enabled:                req.Enabled,
		APIKey:                 trimPtr(req.APIKey),
		ClearAPIKey:            req.ClearAPIKey,
		HMACSecret:             trimPtr(req.HMACSecret),
		ClearHMACSecret:        req.ClearHMACSecret,
		HMACRequired:           req.HMACRequired,
		CustomHeaders:          req.CustomHeaders,
		PGPPrivateKey:          req.PGPPrivateKey,
		ClearPGPPrivateKey:     req.ClearPGPPrivateKey,
		PGPPassphrase:          req.PGPPassphrase,
		ClearPGPPassphrase:     req.ClearPGPPassphrase,
		RetentionDays:          req.RetentionDays,
		HeartbeatRetentionDays: req.HeartbeatRetentionDays,
		StoreRawOnError:        req.StoreRawOnError,
	})
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "endpoint not found")
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSONError(w, http.StatusConflict, "an endpoint with this slug already exists")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid endpoint id")
		return
	}
	if err := s.store.DeleteEndpoint(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "endpoint not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var filter db.EventFilter
	if epStr := q.Get("endpointId"); epStr != "" {
		filter.EndpointID, _ = strconv.ParseInt(epStr, 10, 64)
	}
	filter.Kind = strings.TrimSpace(q.Get("kind"))
	filter.IncludeHeartbeats = q.Get("includeHeartbeats") == "1" || strings.EqualFold(q.Get("includeHeartbeats"), "true")
	filter.Query = q.Get("q")
	filter.Limit, _ = strconv.Atoi(q.Get("limit"))
	filter.Offset, _ = strconv.Atoi(q.Get("offset"))

	events, total, err := s.store.ListEvents(r.Context(), filter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []db.WebhookEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": events,
		"total": total,
	})
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid event id")
		return
	}
	ev, err := s.store.GetEvent(r.Context(), id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "event not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) handleDeleteEvent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid event id")
		return
	}
	if err := s.store.DeleteEvent(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "event not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	defaults := db.RetentionSettings{
		RetentionDays:          s.cfg.RetentionDays,
		HeartbeatRetentionDays: s.cfg.HeartbeatRetentionDays,
	}
	rs, err := s.store.GetRetentionSettings(r.Context(), defaults)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stats, err := s.store.GetStats(r.Context(), s.cfg.DBPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"retention": rs,
		"stats":     stats,
		"interval":  s.cfg.RetentionInterval.String(),
	})
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var rs db.RetentionSettings
	if err := decodeJSONBody(w, r, &rs); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SaveRetentionSettings(r.Context(), rs); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

func (s *Server) handlePurgeNow(w http.ResponseWriter, r *http.Request) {
	deleted := s.retention.RunOnce(r.Context())
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": deleted})
}

type generatePGPRequest struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	Passphrase string `json:"passphrase"`
	Bits       int    `json:"bits"`
}

func (s *Server) handleGeneratePGP(w http.ResponseWriter, r *http.Request) {
	var req generatePGPRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	generated, err := csod.GeneratePGPKeyPair(req.Name, req.Email, req.Passphrase, req.Bits)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, generated)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func derefTrim(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func trimPtr(s *string) *string {
	if s == nil {
		return nil
	}
	v := strings.TrimSpace(*s)
	return &v
}
