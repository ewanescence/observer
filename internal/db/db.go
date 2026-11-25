package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/elematte/observer/internal/crypto"
)

var ErrNotFound = errors.New("not found")

// Store wraps SQLite persistence for endpoints, webhook events, and runtime settings.
type Store struct {
	db  *sql.DB
	box *crypto.Box
}

// Endpoint configures a CSOD webhook listener mounted at /hooks/{Slug}.
type Endpoint struct {
	ID                     int64             `json:"id"`
	Name                   string            `json:"name"`
	Slug                   string            `json:"slug"`
	Enabled                bool              `json:"enabled"`
	APIKey                 string            `json:"apiKey,omitempty"`
	HasAPIKey              bool              `json:"hasApiKey"`
	HMACSecret             string            `json:"hmacSecret,omitempty"`
	HasHMACSecret          bool              `json:"hasHmacSecret"`
	HMACRequired           bool              `json:"hmacRequired"`
	CustomHeaders          map[string]string `json:"customHeaders"`
	PGPPrivateKey          string            `json:"pgpPrivateKey,omitempty"`
	HasPGPPrivateKey       bool              `json:"hasPgpPrivateKey"`
	PGPPassphrase          string            `json:"pgpPassphrase,omitempty"`
	HasPGPPassphrase       bool              `json:"hasPgpPassphrase"`
	RetentionDays          *int              `json:"retentionDays"`
	HeartbeatRetentionDays *int              `json:"heartbeatRetentionDays"`
	StoreRawOnError        bool              `json:"storeRawOnError"`
	CreatedAt              time.Time         `json:"createdAt"`
	UpdatedAt              time.Time         `json:"updatedAt"`
}

// WebhookEvent records a single incoming CSOD webhook delivery, heartbeat, challenge, or error.
type WebhookEvent struct {
	ID               int64     `json:"id"`
	EndpointID       int64     `json:"endpointId"`
	EndpointName     string    `json:"endpointName,omitempty"`
	EndpointSlug     string    `json:"endpointSlug,omitempty"`
	ReceivedAt       time.Time `json:"receivedAt"`
	Kind             string    `json:"kind"` // event | heartbeat | challenge | error
	StatusCode       int       `json:"statusCode"`
	ErrorMessage     string    `json:"errorMessage,omitempty"`
	SubscriptionID   string    `json:"subscriptionId,omitempty"`
	SessionID        string    `json:"sessionId,omitempty"`
	AttemptNumber    int       `json:"attemptNumber"`
	RecordCount      int       `json:"recordCount"`
	EventCases       string    `json:"eventCases,omitempty"`
	WasEncrypted     bool      `json:"wasEncrypted"`
	WasCompressed    bool      `json:"wasCompressed"`
	PGPKeyName       string    `json:"pgpKeyName,omitempty"`
	HeadersJSON      string    `json:"headersJson,omitempty"`
	PayloadJSON      string    `json:"payloadJson,omitempty"`
	RawSizeBytes     int       `json:"rawSizeBytes"`
	DecodedSizeBytes int       `json:"decodedSizeBytes"`
}

// EventFilter narrows event queries in the admin UI.
type EventFilter struct {
	EndpointID        int64
	Kind              string
	IncludeHeartbeats bool
	Query             string
	Limit             int
	Offset            int
}

// RetentionSettings holds global retention periods stored in SQLite.
type RetentionSettings struct {
	RetentionDays          int `json:"retentionDays"`
	HeartbeatRetentionDays int `json:"heartbeatRetentionDays"`
}

// Stats summarizes database usage for the settings view.
type Stats struct {
	TotalEvents       int64 `json:"totalEvents"`
	HeartbeatEvents   int64 `json:"heartbeatEvents"`
	ErrorEvents       int64 `json:"errorEvents"`
	EndpointCount     int64 `json:"endpointCount"`
	DBSizeBytes       int64 `json:"dbSizeBytes"`
	AtRestEncryption  bool  `json:"atRestEncryption"`
}

// Open initializes SQLite at path (creating parent directories if needed) and runs migrations.
func Open(path string, box *crypto.Box) (*Store, error) {
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create db directory: %w", err)
		}
	}

	dsn := path
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dsn += sep + "_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(normal)"

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	s := &Store{db: sqlDB, box: box}
	if err := s.migrate(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping verifies database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS endpoints (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	slug TEXT NOT NULL UNIQUE,
	enabled INTEGER NOT NULL DEFAULT 1,
	api_key_enc TEXT NOT NULL DEFAULT '',
	hmac_secret_enc TEXT NOT NULL DEFAULT '',
	hmac_required INTEGER NOT NULL DEFAULT 1,
	custom_headers_json TEXT NOT NULL DEFAULT '{}',
	pgp_private_key_enc TEXT NOT NULL DEFAULT '',
	pgp_passphrase_enc TEXT NOT NULL DEFAULT '',
	retention_days INTEGER NULL,
	heartbeat_retention_days INTEGER NULL,
	store_raw_on_error INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
	received_at TEXT NOT NULL,
	kind TEXT NOT NULL,
	status_code INTEGER NOT NULL,
	error_message TEXT NOT NULL DEFAULT '',
	subscription_id TEXT NOT NULL DEFAULT '',
	session_id TEXT NOT NULL DEFAULT '',
	attempt_number INTEGER NOT NULL DEFAULT 0,
	record_count INTEGER NOT NULL DEFAULT 0,
	event_cases TEXT NOT NULL DEFAULT '',
	was_encrypted INTEGER NOT NULL DEFAULT 0,
	was_compressed INTEGER NOT NULL DEFAULT 0,
	pgp_key_name TEXT NOT NULL DEFAULT '',
	headers_json TEXT NOT NULL DEFAULT '{}',
	payload_json TEXT NOT NULL DEFAULT '',
	raw_size_bytes INTEGER NOT NULL DEFAULT 0,
	decoded_size_bytes INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_received_at ON webhook_events(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_endpoint_received ON webhook_events(endpoint_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_kind_received ON webhook_events(kind, received_at);

CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

// ListEndpoints returns all endpoints with secret material masked and presence flags populated.
func (s *Store) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, slug, enabled, api_key_enc, hmac_secret_enc, hmac_required,
		       custom_headers_json, pgp_private_key_enc, pgp_passphrase_enc,
		       retention_days, heartbeat_retention_days, store_raw_on_error,
		       created_at, updated_at
		FROM endpoints
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Endpoint
	for rows.Next() {
		ep, err := scanEndpointMasked(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

// GetEndpointBySlug returns an endpoint with decrypted secrets for webhook ingestion.
func (s *Store) GetEndpointBySlug(ctx context.Context, slug string) (Endpoint, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, slug, enabled, api_key_enc, hmac_secret_enc, hmac_required,
		       custom_headers_json, pgp_private_key_enc, pgp_passphrase_enc,
		       retention_days, heartbeat_retention_days, store_raw_on_error,
		       created_at, updated_at
		FROM endpoints
		WHERE slug = ?
	`, slug)
	return s.scanEndpointDecrypted(row)
}

// GetEndpointByID returns an endpoint with decrypted secrets for internal operations.
func (s *Store) GetEndpointByID(ctx context.Context, id int64) (Endpoint, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, slug, enabled, api_key_enc, hmac_secret_enc, hmac_required,
		       custom_headers_json, pgp_private_key_enc, pgp_passphrase_enc,
		       retention_days, heartbeat_retention_days, store_raw_on_error,
		       created_at, updated_at
		FROM endpoints
		WHERE id = ?
	`, id)
	return s.scanEndpointDecrypted(row)
}

// CreateEndpoint persists a new endpoint configuration.
func (s *Store) CreateEndpoint(ctx context.Context, ep Endpoint) (Endpoint, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	apiKeyEnc, err := s.box.Seal(ep.APIKey)
	if err != nil {
		return Endpoint{}, err
	}
	hmacEnc, err := s.box.Seal(ep.HMACSecret)
	if err != nil {
		return Endpoint{}, err
	}
	pgpKeyEnc, err := s.box.Seal(ep.PGPPrivateKey)
	if err != nil {
		return Endpoint{}, err
	}
	pgpPassEnc, err := s.box.Seal(ep.PGPPassphrase)
	if err != nil {
		return Endpoint{}, err
	}
	headersJSON, err := marshalHeaders(ep.CustomHeaders)
	if err != nil {
		return Endpoint{}, err
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO endpoints (
			name, slug, enabled, api_key_enc, hmac_secret_enc, hmac_required,
			custom_headers_json, pgp_private_key_enc, pgp_passphrase_enc,
			retention_days, heartbeat_retention_days, store_raw_on_error,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		ep.Name, ep.Slug, boolToInt(ep.Enabled), apiKeyEnc, hmacEnc, boolToInt(ep.HMACRequired),
		headersJSON, pgpKeyEnc, pgpPassEnc,
		ep.RetentionDays, ep.HeartbeatRetentionDays, boolToInt(ep.StoreRawOnError),
		now, now,
	)
	if err != nil {
		return Endpoint{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Endpoint{}, err
	}
	created, err := s.GetEndpointByID(ctx, id)
	if err != nil {
		return Endpoint{}, err
	}
	return maskEndpoint(created), nil
}

// EndpointPatch specifies updates to an endpoint; nil secret fields preserve existing values.
type EndpointPatch struct {
	Name                   string
	Slug                   string
	Enabled                bool
	APIKey                 *string
	ClearAPIKey            bool
	HMACSecret             *string
	ClearHMACSecret        bool
	HMACRequired           bool
	CustomHeaders          map[string]string
	PGPPrivateKey          *string
	ClearPGPPrivateKey     bool
	PGPPassphrase          *string
	ClearPGPPassphrase     bool
	RetentionDays          *int
	HeartbeatRetentionDays *int
	StoreRawOnError        bool
}

// UpdateEndpoint updates an existing endpoint while preserving omitted secrets.
func (s *Store) UpdateEndpoint(ctx context.Context, id int64, p EndpointPatch) (Endpoint, error) {
	existing, err := s.GetEndpointByID(ctx, id)
	if err != nil {
		return Endpoint{}, err
	}

	apiKey := resolveSecretPatch(existing.APIKey, p.APIKey, p.ClearAPIKey)
	hmacSecret := resolveSecretPatch(existing.HMACSecret, p.HMACSecret, p.ClearHMACSecret)
	pgpKey := resolveSecretPatch(existing.PGPPrivateKey, p.PGPPrivateKey, p.ClearPGPPrivateKey)
	pgpPass := resolveSecretPatch(existing.PGPPassphrase, p.PGPPassphrase, p.ClearPGPPassphrase)

	apiKeyEnc, err := s.box.Seal(apiKey)
	if err != nil {
		return Endpoint{}, err
	}
	hmacEnc, err := s.box.Seal(hmacSecret)
	if err != nil {
		return Endpoint{}, err
	}
	pgpKeyEnc, err := s.box.Seal(pgpKey)
	if err != nil {
		return Endpoint{}, err
	}
	pgpPassEnc, err := s.box.Seal(pgpPass)
	if err != nil {
		return Endpoint{}, err
	}
	headersJSON, err := marshalHeaders(p.CustomHeaders)
	if err != nil {
		return Endpoint{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `
		UPDATE endpoints
		SET name = ?, slug = ?, enabled = ?, api_key_enc = ?, hmac_secret_enc = ?,
		    hmac_required = ?, custom_headers_json = ?, pgp_private_key_enc = ?,
		    pgp_passphrase_enc = ?, retention_days = ?, heartbeat_retention_days = ?,
		    store_raw_on_error = ?, updated_at = ?
		WHERE id = ?
	`,
		p.Name, p.Slug, boolToInt(p.Enabled), apiKeyEnc, hmacEnc,
		boolToInt(p.HMACRequired), headersJSON, pgpKeyEnc,
		pgpPassEnc, p.RetentionDays, p.HeartbeatRetentionDays,
		boolToInt(p.StoreRawOnError), now, id,
	)
	if err != nil {
		return Endpoint{}, err
	}

	updated, err := s.GetEndpointByID(ctx, id)
	if err != nil {
		return Endpoint{}, err
	}
	return maskEndpoint(updated), nil
}

// DeleteEndpoint deletes an endpoint and cascades to its events.
func (s *Store) DeleteEndpoint(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM endpoints WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// InsertEvent stores a processed webhook event, heartbeat, challenge, or error.
func (s *Store) InsertEvent(ctx context.Context, ev WebhookEvent) (int64, error) {
	if ev.ReceivedAt.IsZero() {
		ev.ReceivedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO webhook_events (
			endpoint_id, received_at, kind, status_code, error_message,
			subscription_id, session_id, attempt_number, record_count,
			event_cases, was_encrypted, was_compressed, pgp_key_name,
			headers_json, payload_json, raw_size_bytes, decoded_size_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		ev.EndpointID, ev.ReceivedAt.UTC().Format(time.RFC3339Nano), ev.Kind, ev.StatusCode, ev.ErrorMessage,
		ev.SubscriptionID, ev.SessionID, ev.AttemptNumber, ev.RecordCount,
		ev.EventCases, boolToInt(ev.WasEncrypted), boolToInt(ev.WasCompressed), ev.PGPKeyName,
		ev.HeadersJSON, ev.PayloadJSON, ev.RawSizeBytes, ev.DecodedSizeBytes,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListEvents queries events matching filter criteria and returns the total count.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]WebhookEvent, int64, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	var conds []string
	var args []any

	if f.EndpointID > 0 {
		conds = append(conds, "e.endpoint_id = ?")
		args = append(args, f.EndpointID)
	}
	if f.Kind != "" {
		conds = append(conds, "e.kind = ?")
		args = append(args, f.Kind)
	} else if !f.IncludeHeartbeats {
		conds = append(conds, "e.kind != 'heartbeat'")
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + q + "%"
		conds = append(conds, "(e.payload_json LIKE ? OR e.subscription_id LIKE ? OR e.session_id LIKE ? OR e.event_cases LIKE ? OR e.error_message LIKE ?)")
		args = append(args, like, like, like, like, like)
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	var total int64
	countSQL := "SELECT COUNT(*) FROM webhook_events e " + where
	if err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	querySQL := `
		SELECT e.id, e.endpoint_id, ep.name, ep.slug, e.received_at, e.kind, e.status_code,
		       e.error_message, e.subscription_id, e.session_id, e.attempt_number, e.record_count,
		       e.event_cases, e.was_encrypted, e.was_compressed, e.pgp_key_name,
		       e.headers_json, e.payload_json, e.raw_size_bytes, e.decoded_size_bytes
		FROM webhook_events e
		JOIN endpoints ep ON ep.id = e.endpoint_id
		` + where + `
		ORDER BY e.received_at DESC, e.id DESC
		LIMIT ? OFFSET ?
	`
	qArgs := append(append([]any{}, args...), f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, querySQL, qArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []WebhookEvent
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, ev)
	}
	return events, total, rows.Err()
}

// GetEvent returns a single event by ID.
func (s *Store) GetEvent(ctx context.Context, id int64) (WebhookEvent, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT e.id, e.endpoint_id, ep.name, ep.slug, e.received_at, e.kind, e.status_code,
		       e.error_message, e.subscription_id, e.session_id, e.attempt_number, e.record_count,
		       e.event_cases, e.was_encrypted, e.was_compressed, e.pgp_key_name,
		       e.headers_json, e.payload_json, e.raw_size_bytes, e.decoded_size_bytes
		FROM webhook_events e
		JOIN endpoints ep ON ep.id = e.endpoint_id
		WHERE e.id = ?
	`, id)
	ev, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return WebhookEvent{}, ErrNotFound
	}
	return ev, err
}

// DeleteEvent deletes a single event by ID.
func (s *Store) DeleteEvent(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM webhook_events WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetRetentionSettings returns stored global retention settings or defaults.
func (s *Store) GetRetentionSettings(ctx context.Context, defaults RetentionSettings) (RetentionSettings, error) {
	out := defaults
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings WHERE key IN ('retention_days', 'heartbeat_retention_days')`)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return out, err
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			continue
		}
		switch k {
		case "retention_days":
			out.RetentionDays = n
		case "heartbeat_retention_days":
			out.HeartbeatRetentionDays = n
		}
	}
	return out, rows.Err()
}

// SaveRetentionSettings persists global retention periods.
func (s *Store) SaveRetentionSettings(ctx context.Context, rs RetentionSettings) error {
	if rs.RetentionDays < 1 || rs.HeartbeatRetentionDays < 1 {
		return errors.New("retention days must be >= 1")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for k, v := range map[string]int{
		"retention_days":           rs.RetentionDays,
		"heartbeat_retention_days": rs.HeartbeatRetentionDays,
	} {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO settings (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, k, strconv.Itoa(v)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PurgeExpired deletes events exceeding their endpoint-specific or global retention window.
func (s *Store) PurgeExpired(ctx context.Context, now time.Time, defaults RetentionSettings) (int64, error) {
	rs, err := s.GetRetentionSettings(ctx, defaults)
	if err != nil {
		return 0, err
	}

	endpoints, err := s.ListEndpoints(ctx)
	if err != nil {
		return 0, err
	}

	var deletedTotal int64
	for _, ep := range endpoints {
		evDays := rs.RetentionDays
		if ep.RetentionDays != nil && *ep.RetentionDays >= 1 {
			evDays = *ep.RetentionDays
		}
		hbDays := rs.HeartbeatRetentionDays
		if ep.HeartbeatRetentionDays != nil && *ep.HeartbeatRetentionDays >= 1 {
			hbDays = *ep.HeartbeatRetentionDays
		}

		evCutoff := now.UTC().Add(-time.Duration(evDays) * 24 * time.Hour).Format(time.RFC3339Nano)
		hbCutoff := now.UTC().Add(-time.Duration(hbDays) * 24 * time.Hour).Format(time.RFC3339Nano)

		res, err := s.db.ExecContext(ctx, `
			DELETE FROM webhook_events
			WHERE endpoint_id = ?
			  AND (
			    (kind IN ('heartbeat', 'challenge') AND received_at < ?)
			    OR (kind NOT IN ('heartbeat', 'challenge') AND received_at < ?)
			  )
		`, ep.ID, hbCutoff, evCutoff)
		if err != nil {
			return deletedTotal, err
		}
		n, _ := res.RowsAffected()
		deletedTotal += n
	}

	if deletedTotal > 0 {
		_, _ = s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	return deletedTotal, nil
}

// GetStats returns aggregate row counts and database file size.
func (s *Store) GetStats(ctx context.Context, dbPath string) (Stats, error) {
	st := Stats{AtRestEncryption: s.box.Enabled()}
	if err := s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN kind = 'heartbeat' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN kind = 'error' THEN 1 ELSE 0 END), 0)
		FROM webhook_events
	`).Scan(&st.TotalEvents, &st.HeartbeatEvents, &st.ErrorEvents); err != nil {
		return st, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM endpoints`).Scan(&st.EndpointCount); err != nil {
		return st, err
	}
	if info, err := os.Stat(dbPath); err == nil {
		st.DBSizeBytes = info.Size()
	}
	return st, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanEndpointRaw(sc scanner) (Endpoint, string, string, string, string, error) {
	var ep Endpoint
	var enabledInt, hmacReqInt, storeRawInt int
	var apiEnc, hmacEnc, headersJSON, pgpKeyEnc, pgpPassEnc string
	var retDays, hbRetDays sql.NullInt64
	var createdStr, updatedStr string

	err := sc.Scan(
		&ep.ID, &ep.Name, &ep.Slug, &enabledInt,
		&apiEnc, &hmacEnc, &hmacReqInt,
		&headersJSON, &pgpKeyEnc, &pgpPassEnc,
		&retDays, &hbRetDays, &storeRawInt,
		&createdStr, &updatedStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Endpoint{}, "", "", "", "", ErrNotFound
		}
		return Endpoint{}, "", "", "", "", err
	}

	ep.Enabled = enabledInt != 0
	ep.HMACRequired = hmacReqInt != 0
	ep.StoreRawOnError = storeRawInt != 0
	ep.CustomHeaders = make(map[string]string)
	if headersJSON != "" {
		_ = json.Unmarshal([]byte(headersJSON), &ep.CustomHeaders)
	}
	if retDays.Valid {
		v := int(retDays.Int64)
		ep.RetentionDays = &v
	}
	if hbRetDays.Valid {
		v := int(hbRetDays.Int64)
		ep.HeartbeatRetentionDays = &v
	}
	ep.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdStr)
	ep.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedStr)
	return ep, apiEnc, hmacEnc, pgpKeyEnc, pgpPassEnc, nil
}

func scanEndpointMasked(sc scanner) (Endpoint, error) {
	ep, apiEnc, hmacEnc, pgpKeyEnc, pgpPassEnc, err := scanEndpointRaw(sc)
	if err != nil {
		return Endpoint{}, err
	}
	ep.HasAPIKey = apiEnc != ""
	ep.HasHMACSecret = hmacEnc != ""
	ep.HasPGPPrivateKey = pgpKeyEnc != ""
	ep.HasPGPPassphrase = pgpPassEnc != ""
	return ep, nil
}

func (s *Store) scanEndpointDecrypted(sc scanner) (Endpoint, error) {
	ep, apiEnc, hmacEnc, pgpKeyEnc, pgpPassEnc, err := scanEndpointRaw(sc)
	if err != nil {
		return Endpoint{}, err
	}
	if ep.APIKey, err = s.box.Open(apiEnc); err != nil {
		return Endpoint{}, err
	}
	if ep.HMACSecret, err = s.box.Open(hmacEnc); err != nil {
		return Endpoint{}, err
	}
	if ep.PGPPrivateKey, err = s.box.Open(pgpKeyEnc); err != nil {
		return Endpoint{}, err
	}
	if ep.PGPPassphrase, err = s.box.Open(pgpPassEnc); err != nil {
		return Endpoint{}, err
	}
	ep.HasAPIKey = ep.APIKey != ""
	ep.HasHMACSecret = ep.HMACSecret != ""
	ep.HasPGPPrivateKey = ep.PGPPrivateKey != ""
	ep.HasPGPPassphrase = ep.PGPPassphrase != ""
	return ep, nil
}

func maskEndpoint(ep Endpoint) Endpoint {
	ep.APIKey = ""
	ep.HMACSecret = ""
	ep.PGPPrivateKey = ""
	ep.PGPPassphrase = ""
	return ep
}

func scanEvent(sc scanner) (WebhookEvent, error) {
	var ev WebhookEvent
	var receivedStr string
	var encInt, compInt int
	err := sc.Scan(
		&ev.ID, &ev.EndpointID, &ev.EndpointName, &ev.EndpointSlug, &receivedStr,
		&ev.Kind, &ev.StatusCode, &ev.ErrorMessage,
		&ev.SubscriptionID, &ev.SessionID, &ev.AttemptNumber, &ev.RecordCount,
		&ev.EventCases, &encInt, &compInt, &ev.PGPKeyName,
		&ev.HeadersJSON, &ev.PayloadJSON, &ev.RawSizeBytes, &ev.DecodedSizeBytes,
	)
	if err != nil {
		return WebhookEvent{}, err
	}
	ev.WasEncrypted = encInt != 0
	ev.WasCompressed = compInt != 0
	ev.ReceivedAt, _ = time.Parse(time.RFC3339Nano, receivedStr)
	return ev, nil
}

func marshalHeaders(h map[string]string) (string, error) {
	if h == nil {
		h = map[string]string{}
	}
	b, err := json.Marshal(h)
	return string(b), err
}

func resolveSecretPatch(existing string, incoming *string, clear bool) string {
	if clear {
		return ""
	}
	if incoming != nil && *incoming != "" {
		return *incoming
	}
	return existing
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
