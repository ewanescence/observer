package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

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

func (s *Server) actorFromRequest(r *http.Request) (string, string, string) {
	uid := strings.TrimSpace(r.Header.Get("X-Auth-User"))
	email := strings.TrimSpace(r.Header.Get("X-Auth-Email"))
	hdrName := strings.TrimSpace(r.Header.Get("X-Auth-Name"))
	if hdrName == "" {
		hdrName = strings.TrimSpace(r.Header.Get("X-Auth-Username"))
	}
	if uid == "" && !s.cfg.TrustForwardAuth {
		uid = "local-dev"
	}
	return uid, email, hdrName
}

func (s *Server) resolveActor(r *http.Request) (string, string, string) {
	uid, email, hdrName := s.actorFromRequest(r)
	if uid == "" {
		return "", email, hdrName
	}

	ctx := r.Context()
	cached, err := s.store.GetUser(ctx, uid)
	needsSync := err != nil || cached.DisplayName == "" || cached.SyncedAt.IsZero() || time.Since(cached.SyncedAt) > 15*time.Minute

	if s.autenticoClient.Enabled() && needsSync {
		lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		prof, lookupErr := s.autenticoClient.LookupUser(lookupCtx, uid)
		cancel()
		if lookupErr == nil {
			resolvedEmail := email
			if resolvedEmail == "" {
				resolvedEmail = prof.Email
			}
			_ = s.store.SyncUserFromAutentico(ctx, uid, resolvedEmail, prof.DisplayName)
			return uid, resolvedEmail, prof.DisplayName
		}
		log.Printf("autentico user lookup failed for %s: %v", uid, lookupErr)
	}

	_ = s.store.UpsertUser(ctx, uid, email, hdrName)
	if err == nil {
		if email == "" {
			email = cached.Email
		}
		if hdrName == "" {
			hdrName = cached.DisplayName
		}
	}
	return uid, email, hdrName
}

func (s *Server) recordAudit(r *http.Request, action, targetType, targetID, targetLabel, details string) {
	uid, email, _ := s.resolveActor(r)
	_ = s.store.InsertAuditLog(r.Context(), db.AuditLog{
		ActorID:     uid,
		ActorEmail:  email,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		TargetLabel: targetLabel,
		Details:     details,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	_, email, displayName := s.resolveActor(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"email":            email,
		"displayName":      displayName,
		"forwardAuthTrust": s.cfg.TrustForwardAuth,
		"logoutPath":       s.cfg.AutenticoLogoutPath,
		"centralLogoutUrl": s.cfg.CentralLogoutURL,
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	portals, err := s.store.GetPortalHierarchy(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if portals == nil {
		portals = []db.PortalSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"portals": portals,
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
	Portal                 string            `json:"portal"`
	Environment            string            `json:"environment"`
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
	req.Portal = strings.TrimSpace(req.Portal)
	if req.Portal == "" {
		req.Portal = "Default"
	}
	if len(req.Portal) > 80 {
		return errors.New("portal must be <= 80 characters")
	}

	req.Environment = strings.TrimSpace(req.Environment)
	if req.Environment == "" {
		req.Environment = "Production"
	}
	if len(req.Environment) > 40 {
		return errors.New("environment must be <= 40 characters")
	}

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

func endpointLabel(portal, env, name, slug string) string {
	return fmt.Sprintf("%s > %s > %s (/hooks/%s)", portal, env, name, slug)
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
		Portal:                 req.Portal,
		Environment:            req.Environment,
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
		writeEndpointMutationError(w, err)
		return
	}

	s.recordAudit(r, "endpoint.create", "endpoint", strconv.FormatInt(created.ID, 10),
		endpointLabel(created.Portal, created.Environment, created.Name, created.Slug),
		fmt.Sprintf("enabled=%v, hmacRequired=%v, hasPgp=%v", created.Enabled, created.HMACRequired, created.HasPGPPrivateKey))

	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "endpoint")
	if !ok {
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
		Portal:                 req.Portal,
		Environment:            req.Environment,
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
		writeEndpointMutationError(w, err)
		return
	}

	s.recordAudit(r, "endpoint.update", "endpoint", strconv.FormatInt(updated.ID, 10),
		endpointLabel(updated.Portal, updated.Environment, updated.Name, updated.Slug),
		fmt.Sprintf("enabled=%v, hmacRequired=%v, hasPgp=%v", updated.Enabled, updated.HMACRequired, updated.HasPGPPrivateKey))

	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "endpoint")
	if !ok {
		return
	}
	existing, err := s.store.GetEndpointByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "endpoint not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
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

	s.recordAudit(r, "endpoint.delete", "endpoint", strconv.FormatInt(id, 10),
		endpointLabel(existing.Portal, existing.Environment, existing.Name, existing.Slug),
		"deleted endpoint and associated events")

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var filter db.EventFilter
	filter.Portal = strings.TrimSpace(q.Get("portal"))
	filter.Environment = strings.TrimSpace(q.Get("environment"))
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
	id, ok := parsePathID(w, r, "event")
	if !ok {
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
	id, ok := parsePathID(w, r, "event")
	if !ok {
		return
	}
	existing, err := s.store.GetEvent(r.Context(), id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "event not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
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

	s.recordAudit(r, "event.delete", "event", strconv.FormatInt(id, 10),
		endpointLabel(existing.EndpointPortal, existing.EndpointEnvironment, existing.EndpointName, existing.EndpointSlug),
		fmt.Sprintf("deleted %s #%d", existing.Kind, id))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var filter db.AuditFilter
	filter.Action = strings.TrimSpace(q.Get("action"))
	filter.Query = q.Get("q")
	filter.Limit, _ = strconv.Atoi(q.Get("limit"))
	filter.Offset, _ = strconv.Atoi(q.Get("offset"))

	items, total, err := s.store.ListAuditLogs(r.Context(), filter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []db.AuditLog{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
	})
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

	s.recordAudit(r, "settings.update", "settings", "retention", "Global Retention",
		fmt.Sprintf("retentionDays=%d, heartbeatRetentionDays=%d", rs.RetentionDays, rs.HeartbeatRetentionDays))

	writeJSON(w, http.StatusOK, rs)
}

func (s *Server) handlePurgeNow(w http.ResponseWriter, r *http.Request) {
	deleted := s.retention.RunOnce(r.Context())
	s.recordAudit(r, "retention.purge", "settings", "retention", "Manual Purge",
		fmt.Sprintf("deleted=%d expired event(s)", deleted))
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": deleted})
}

type generatePGPRequest struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	Passphrase string `json:"passphrase"`
	Bits       int    `json:"bits"`
	ValidDays  int    `json:"validDays"`
}

func (s *Server) handleGeneratePGP(w http.ResponseWriter, r *http.Request) {
	var req generatePGPRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	generated, err := csod.GeneratePGPKeyPair(req.Name, req.Email, req.Passphrase, req.Bits, req.ValidDays)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.recordAudit(r, "pgp.generate", "pgp_key", generated.KeyID, req.Name,
		fmt.Sprintf("bits=%d, validDays=%d, fingerprint=%s", req.Bits, req.ValidDays, generated.Fingerprint))

	writeJSON(w, http.StatusOK, generated)
}

func parsePathID(w http.ResponseWriter, r *http.Request, label string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid "+label+" id")
		return 0, false
	}
	return id, true
}

func writeEndpointMutationError(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	if strings.Contains(strings.ToLower(err.Error()), "unique") {
		writeJSONError(w, http.StatusConflict, "an endpoint with this slug already exists")
		return
	}
	writeJSONError(w, http.StatusInternalServerError, err.Error())
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
