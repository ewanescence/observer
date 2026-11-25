package server_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elematte/observer/internal/config"
	"github.com/elematte/observer/internal/crypto"
	"github.com/elematte/observer/internal/db"
	"github.com/elematte/observer/internal/retention"
	"github.com/elematte/observer/internal/server"
)

func newTestServer(t *testing.T, trustForwardAuth bool) (*server.Server, *db.Store, *retention.Worker) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	box, err := crypto.NewBox(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("new box: %v", err)
	}
	store, err := db.Open(dbPath, box)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := config.Config{
		DBPath:                 dbPath,
		TrustForwardAuth:       trustForwardAuth,
		AutenticoLogoutPath:    "/_autentico/app-123/logout",
		CentralLogoutURL:       "https://auth.example.com/oauth2/logout",
		RetentionDays:          30,
		HeartbeatRetentionDays: 1,
		RetentionInterval:      time.Hour,
		MaxBodyBytes:           1024 * 1024,
		MaxDecompressedBytes:   5 * 1024 * 1024,
		AllowedUsers:           map[string]struct{}{},
	}
	ret := retention.NewWorker(store, db.RetentionSettings{
		RetentionDays:          cfg.RetentionDays,
		HeartbeatRetentionDays: cfg.HeartbeatRetentionDays,
	}, cfg.RetentionInterval)
	srv := server.New(cfg, store, ret)
	return srv, store, ret
}

func TestForwardAuthAndCSRFProtection(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	h := srv.Handler()

	// Unauthenticated request to /api/endpoints fails closed
	req := httptest.NewRequest(http.MethodGet, "/api/endpoints", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without X-Auth-User, got %d", rec.Code)
	}

	// Authenticated GET works
	req = httptest.NewRequest(http.MethodGet, "/api/endpoints", nil)
	req.Header.Set("X-Auth-User", "user-123")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with X-Auth-User, got %d", rec.Code)
	}

	// Mutating request without X-Requested-With is blocked (CSRF defense)
	req = httptest.NewRequest(http.MethodPost, "/api/endpoints", strings.NewReader(`{"name":"A","slug":"a"}`))
	req.Header.Set("X-Auth-User", "user-123")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF header, got %d", rec.Code)
	}
}

func TestEndToEndChallengeWebhookAndRetention(t *testing.T) {
	srv, store, ret := newTestServer(t, true)
	h := srv.Handler()

	secret := base64.StdEncoding.EncodeToString([]byte("endpoint-secret"))
	apiKey := "c90d4c31b21143b1b22f1addf2932536"
	ep, err := store.CreateEndpoint(context.Background(), db.Endpoint{
		Name:          "Training",
		Slug:          "training",
		Enabled:       true,
		APIKey:        apiKey,
		HMACSecret:    secret,
		HMACRequired:  true,
		CustomHeaders: map[string]string{"x-csod-authentication": "tok1"},
	})
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}

	// 1. Token Challenge
	req := httptest.NewRequest(http.MethodPost, "/hooks/training?v=1", nil)
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("x-csod-authentication", "tok1")
	req.Header.Set("x-challenge-sha256", "dbq2kjiql2c4")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for challenge, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("x-challenge-sha256") == "" {
		t.Fatal("expected x-challenge-sha256 response header")
	}

	// 2. Gzipped + HMAC-signed TrainingCompleted webhook
	payload := `{"subscriptionId":"sub-1","sessionId":"sess-1","attemptNumber":1,"records":[{"offset":1,"value":{"lmsEventsCase":"TrainingCompleted"}}]}`
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(payload))
	_ = zw.Close()
	raw := gz.Bytes()

	sum := sha256.Sum256(raw)
	bodyHash := base64.StdEncoding.EncodeToString(sum[:])
	dateVal := "Fri, 03 May 2024 21:43:04 GMT"
	canonical := "POST\n/hooks/training\n" + dateVal + ";" + bodyHash + ";tok1"
	keyBytes, _ := base64.StdEncoding.DecodeString(secret)
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(canonical))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req = httptest.NewRequest(http.MethodPost, "/hooks/training", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Date", dateVal)
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("x-csod-authentication", "tok1")
	req.Header.Set("x-content-sha256", bodyHash)
	req.Header.Set("Authorization", "HMAC-SHA256 Credential="+apiKey+"&SignedHeaders=Date;x-content-sha256;x-csod-authentication&Signature="+sig)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for webhook, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. Verify stored in SQLite via admin API
	req = httptest.NewRequest(http.MethodGet, "/api/events?includeHeartbeats=1", nil)
	req.Header.Set("X-Auth-User", "admin")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 listing events, got %d", rec.Code)
	}
	var listRes struct {
		Total int64             `json:"total"`
		Items []db.WebhookEvent `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listRes); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if listRes.Total != 2 {
		t.Fatalf("expected 2 stored items (challenge + event), got %d", listRes.Total)
	}

	// 4. Insert old event and verify retention purge deletes only expired event
	_, err = store.InsertEvent(context.Background(), db.WebhookEvent{
		EndpointID: ep.ID,
		ReceivedAt: time.Now().UTC().Add(-40 * 24 * time.Hour),
		Kind:       "event",
		StatusCode: 200,
	})
	if err != nil {
		t.Fatalf("insert old event: %v", err)
	}
	purged := ret.RunOnce(context.Background())
	if purged != 1 {
		t.Fatalf("expected 1 purged event, got %d", purged)
	}
}

func TestGeneratePGPEndpoint(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/pgp/generate", strings.NewReader(`{"name":"Test","email":"t@example.com","passphrase":"secret","bits":2048}`))
	req.Header.Set("X-Auth-User", "admin")
	req.Header.Set("X-Requested-With", "observer")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		PublicKey   string `json:"publicKey"`
		PrivateKey  string `json:"privateKey"`
		KeyID       string `json:"keyId"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !strings.Contains(out.PublicKey, "BEGIN PGP PUBLIC KEY BLOCK") || !strings.Contains(out.PrivateKey, "BEGIN PGP PRIVATE KEY BLOCK") {
		t.Fatalf("unexpected key output: %+v", out)
	}
}

func TestPortalHierarchySummaryAndAuditLog(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	h := srv.Handler()

	// 1. Check /api/me hides userId and exposes email + logoutPath
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("X-Auth-User", "xid-secret-123")
	req.Header.Set("X-Auth-Email", "alice@example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/me, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "xid-secret-123") {
		t.Fatalf("expected userId not to be returned by /api/me: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "alice@example.com") || !strings.Contains(rec.Body.String(), "/_autentico/app-123/logout") {
		t.Fatalf("unexpected /api/me payload: %s", rec.Body.String())
	}

	// 2. Create two endpoints in different environments under Acme Corp
	for _, body := range []string{
		`{"portal":"Acme Corp","environment":"Production","name":"Training","slug":"acme-prod-training","enabled":true,"hmacRequired":false,"customHeaders":{}}`,
		`{"portal":"Acme Corp","environment":"Pilot","name":"Employee","slug":"acme-pilot-emp","enabled":true,"hmacRequired":false,"customHeaders":{}}`,
	} {
		req = httptest.NewRequest(http.MethodPost, "/api/endpoints", strings.NewReader(body))
		req.Header.Set("X-Auth-User", "xid-1")
		req.Header.Set("X-Auth-Email", "alice@example.com")
		req.Header.Set("X-Requested-With", "observer")
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201 creating endpoint, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 3. Send event to Pilot endpoint
	req = httptest.NewRequest(http.MethodPost, "/hooks/acme-pilot-emp", strings.NewReader(`{"subscriptionId":"s1","records":[{"offset":1,"value":{"employeeEventsCase":"EmployeeCreated"}}]}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 ingesting event, got %d: %s", rec.Code, rec.Body.String())
	}

	// 4. Verify /api/summary groups Portal > Environment > Endpoint with counts
	req = httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	req.Header.Set("X-Auth-User", "xid-1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/summary, got %d", rec.Code)
	}
	var sumRes struct {
		Portals []db.PortalSummary `json:"portals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sumRes); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	if len(sumRes.Portals) != 1 || sumRes.Portals[0].Portal != "Acme Corp" || sumRes.Portals[0].EventCount != 1 || len(sumRes.Portals[0].Environments) != 2 {
		t.Fatalf("unexpected portal summary: %+v", sumRes.Portals)
	}

	// 5. Verify /api/events filters by portal & environment
	req = httptest.NewRequest(http.MethodGet, "/api/events?portal=Acme+Corp&environment=Production", nil)
	req.Header.Set("X-Auth-User", "xid-1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"total":0`) {
		t.Fatalf("expected 0 events in Production, got %s", rec.Body.String())
	}

	// 6. Verify /api/audit recorded both endpoint.create operations with actorEmail
	req = httptest.NewRequest(http.MethodGet, "/api/audit?action=endpoint.create", nil)
	req.Header.Set("X-Auth-User", "xid-1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/audit, got %d", rec.Code)
	}
	var auditRes struct {
		Total int64         `json:"total"`
		Items []db.AuditLog `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditRes); err != nil {
		t.Fatalf("unmarshal audit: %v", err)
	}
	if auditRes.Total != 2 || auditRes.Items[0].ActorEmail != "alice@example.com" || auditRes.Items[0].ActorName != "alice@example.com" {
		t.Fatalf("unexpected audit log response: %+v", auditRes)
	}

	// 7. Map xid-1 to a friendly display name and verify audit log + /api/me reflect it
	req = httptest.NewRequest(http.MethodPut, "/api/users/xid-1", strings.NewReader(`{"displayName":"Alice Support"}`))
	req.Header.Set("X-Auth-User", "xid-1")
	req.Header.Set("X-Requested-With", "observer")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 renaming user, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/audit?action=endpoint.create", nil)
	req.Header.Set("X-Auth-User", "xid-1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &auditRes); err != nil {
		t.Fatalf("unmarshal audit after rename: %v", err)
	}
	if auditRes.Items[0].ActorName != "Alice Support" {
		t.Fatalf("expected ActorName 'Alice Support', got %q", auditRes.Items[0].ActorName)
	}
}
