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
