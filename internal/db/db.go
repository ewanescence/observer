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

// Store wraps SQLite persistence for endpoints, webhook events, audit logs, and runtime settings.
type Store struct {
	db  *sql.DB
	box *crypto.Box
}

// Endpoint configures a CSOD webhook listener mounted at /hooks/{Slug}.
type Endpoint struct {
	ID                     int64             `json:"id"`
	Portal                 string            `json:"portal"`
	Environment            string            `json:"environment"`
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

// EndpointSummary enriches an endpoint with live event counts.
type EndpointSummary struct {
	Endpoint
	EventCount     int64      `json:"eventCount"`
	HeartbeatCount int64      `json:"heartbeatCount"`
	ChallengeCount int64      `json:"challengeCount"`
	ErrorCount     int64      `json:"errorCount"`
	LastReceivedAt *time.Time `json:"lastReceivedAt,omitempty"`
}

// EnvironmentSummary aggregates endpoints and event counts for a Portal > Environment.
type EnvironmentSummary struct {
	Environment    string            `json:"environment"`
	EndpointCount  int               `json:"endpointCount"`
	EnabledCount   int               `json:"enabledCount"`
	EventCount     int64             `json:"eventCount"`
	HeartbeatCount int64             `json:"heartbeatCount"`
	ChallengeCount int64             `json:"challengeCount"`
	ErrorCount     int64             `json:"errorCount"`
	LastReceivedAt *time.Time        `json:"lastReceivedAt,omitempty"`
	Endpoints      []EndpointSummary `json:"endpoints"`
}

// PortalSummary aggregates environments and event counts for a Portal.
type PortalSummary struct {
	Portal         string               `json:"portal"`
	EndpointCount  int                  `json:"endpointCount"`
	EnabledCount   int                  `json:"enabledCount"`
	EventCount     int64                `json:"eventCount"`
	HeartbeatCount int64                `json:"heartbeatCount"`
	ChallengeCount int64                `json:"challengeCount"`
	ErrorCount     int64                `json:"errorCount"`
	LastReceivedAt *time.Time           `json:"lastReceivedAt,omitempty"`
	Environments   []EnvironmentSummary `json:"environments"`
}

// WebhookEvent records a single incoming CSOD webhook delivery, heartbeat, challenge, or error.
type WebhookEvent struct {
	ID                  int64     `json:"id"`
	EndpointID          int64     `json:"endpointId"`
	EndpointPortal      string    `json:"endpointPortal,omitempty"`
	EndpointEnvironment string    `json:"endpointEnvironment,omitempty"`
	EndpointName        string    `json:"endpointName,omitempty"`
	EndpointSlug        string    `json:"endpointSlug,omitempty"`
	ReceivedAt          time.Time `json:"receivedAt"`
	Kind                string    `json:"kind"` // event | heartbeat | challenge | error
	StatusCode          int       `json:"statusCode"`
	ErrorMessage        string    `json:"errorMessage,omitempty"`
	SubscriptionID      string    `json:"subscriptionId,omitempty"`
	SessionID           string    `json:"sessionId,omitempty"`
	AttemptNumber       int       `json:"attemptNumber"`
	RecordCount         int       `json:"recordCount"`
	EventCases          string    `json:"eventCases,omitempty"`
	WasEncrypted        bool      `json:"wasEncrypted"`
	WasCompressed       bool      `json:"wasCompressed"`
	PGPKeyName          string    `json:"pgpKeyName,omitempty"`
	HeadersJSON         string    `json:"headersJson,omitempty"`
	PayloadJSON         string    `json:"payloadJson,omitempty"`
	RawSizeBytes        int       `json:"rawSizeBytes"`
	DecodedSizeBytes    int       `json:"decodedSizeBytes"`
}

// EventFilter narrows event queries in the admin UI.
type EventFilter struct {
	Portal            string
	Environment       string
	EndpointID        int64
	Kind              string
	IncludeHeartbeats bool
	Query             string
	Limit             int
	Offset            int
}

// AuditLog records an administrative operation performed through Observer.
type AuditLog struct {
	ID          int64     `json:"id"`
	OccurredAt  time.Time `json:"occurredAt"`
	ActorID     string    `json:"actorId"`
	ActorEmail  string    `json:"actorEmail"`
	ActorName   string    `json:"actorName"`
	Action      string    `json:"action"`
	TargetType  string    `json:"targetType"`
	TargetID    string    `json:"targetId"`
	TargetLabel string    `json:"targetLabel"`
	Details     string    `json:"details"`
}

// User caches read-only identity fields synced from Autentico for an X-Auth-User ID.
type User struct {
	UserID      string    `json:"userId"`
	Email       string    `json:"email"`
	DisplayName string    `json:"displayName"`
	SyncedAt    time.Time `json:"syncedAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
}

// AuditFilter narrows audit log queries.
type AuditFilter struct {
	Action string
	Query  string
	Limit  int
	Offset int
}

// RetentionSettings holds global retention periods stored in SQLite.
type RetentionSettings struct {
	RetentionDays          int `json:"retentionDays"`
	HeartbeatRetentionDays int `json:"heartbeatRetentionDays"`
}

// Stats summarizes database usage for the settings view.
type Stats struct {
	TotalEvents      int64 `json:"totalEvents"`
	HeartbeatEvents  int64 `json:"heartbeatEvents"`
	ErrorEvents      int64 `json:"errorEvents"`
	EndpointCount    int64 `json:"endpointCount"`
	AuditLogCount    int64 `json:"auditLogCount"`
	DBSizeBytes      int64 `json:"dbSizeBytes"`
	AtRestEncryption bool  `json:"atRestEncryption"`
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
	portal TEXT NOT NULL DEFAULT 'Default',
	environment TEXT NOT NULL DEFAULT 'Production',
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

CREATE TABLE IF NOT EXISTS audit_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	occurred_at TEXT NOT NULL,
	actor_id TEXT NOT NULL DEFAULT '',
	actor_email TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL,
	target_type TEXT NOT NULL,
	target_id TEXT NOT NULL DEFAULT '',
	target_label TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON audit_logs(occurred_at DESC);

CREATE TABLE IF NOT EXISTS users (
	user_id TEXT PRIMARY KEY,
	email TEXT NOT NULL DEFAULT '',
	display_name TEXT NOT NULL DEFAULT '',
	synced_at TEXT NOT NULL DEFAULT '',
	last_seen_at TEXT NOT NULL
);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}

	userCols, err := s.tableColumns(ctx, "users")
	if err != nil {
		return err
	}
	if !userCols["synced_at"] {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN synced_at TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}

	// Upgrade existing databases created before portal/environment columns existed.
	cols, err := s.tableColumns(ctx, "endpoints")
	if err != nil {
		return err
	}
	if !cols["portal"] {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE endpoints ADD COLUMN portal TEXT NOT NULL DEFAULT 'Default'`); err != nil {
			return err
		}
	}
	if !cols["environment"] {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE endpoints ADD COLUMN environment TEXT NOT NULL DEFAULT 'Production'`); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_endpoints_portal_env ON endpoints(portal, environment, name)`)
	return err
}

func (s *Store) tableColumns(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[strings.ToLower(name)] = true
	}
	return cols, rows.Err()
}

// ListEndpoints returns all endpoints ordered by Portal > Environment > Name with masked secrets.
func (s *Store) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, portal, environment, name, slug, enabled, api_key_enc, hmac_secret_enc, hmac_required,
		       custom_headers_json, pgp_private_key_enc, pgp_passphrase_enc,
		       retention_days, heartbeat_retention_days, store_raw_on_error,
		       created_at, updated_at
		FROM endpoints
		ORDER BY lower(portal) ASC, lower(environment) ASC, lower(name) ASC, id ASC
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

// GetPortalHierarchy returns endpoints and event counts organized as Portal > Environment > Endpoint.
func (s *Store) GetPortalHierarchy(ctx context.Context) ([]PortalSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ep.id, ep.portal, ep.environment, ep.name, ep.slug, ep.enabled,
		       ep.api_key_enc, ep.hmac_secret_enc, ep.hmac_required,
		       ep.custom_headers_json, ep.pgp_private_key_enc, ep.pgp_passphrase_enc,
		       ep.retention_days, ep.heartbeat_retention_days, ep.store_raw_on_error,
		       ep.created_at, ep.updated_at,
		       COALESCE(SUM(CASE WHEN ev.kind = 'event' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN ev.kind = 'heartbeat' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN ev.kind = 'challenge' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN ev.kind = 'error' THEN 1 ELSE 0 END), 0),
		       MAX(ev.received_at)
		FROM endpoints ep
		LEFT JOIN webhook_events ev ON ev.endpoint_id = ep.id
		GROUP BY ep.id
		ORDER BY lower(ep.portal) ASC, lower(ep.environment) ASC, lower(ep.name) ASC, ep.id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var portals []PortalSummary
	portalIdx := make(map[string]int)
	envIdx := make(map[string]int)

	for rows.Next() {
		var es EndpointSummary
		var enabledInt, hmacReqInt, storeRawInt int
		var apiEnc, hmacEnc, headersJSON, pgpKeyEnc, pgpPassEnc string
		var retDays, hbRetDays sql.NullInt64
		var createdStr, updatedStr string
		var lastRecv sql.NullString

		if err := rows.Scan(
			&es.ID, &es.Portal, &es.Environment, &es.Name, &es.Slug, &enabledInt,
			&apiEnc, &hmacEnc, &hmacReqInt,
			&headersJSON, &pgpKeyEnc, &pgpPassEnc,
			&retDays, &hbRetDays, &storeRawInt,
			&createdStr, &updatedStr,
			&es.EventCount, &es.HeartbeatCount, &es.ChallengeCount, &es.ErrorCount, &lastRecv,
		); err != nil {
			return nil, err
		}

		es.Enabled = enabledInt != 0
		es.HMACRequired = hmacReqInt != 0
		es.StoreRawOnError = storeRawInt != 0
		es.HasAPIKey = apiEnc != ""
		es.HasHMACSecret = hmacEnc != ""
		es.HasPGPPrivateKey = pgpKeyEnc != ""
		es.HasPGPPassphrase = pgpPassEnc != ""
		es.CustomHeaders = make(map[string]string)
		if headersJSON != "" {
			_ = json.Unmarshal([]byte(headersJSON), &es.CustomHeaders)
		}
		if retDays.Valid {
			v := int(retDays.Int64)
			es.RetentionDays = &v
		}
		if hbRetDays.Valid {
			v := int(hbRetDays.Int64)
			es.HeartbeatRetentionDays = &v
		}
		es.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdStr)
		es.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedStr)
		if lastRecv.Valid && lastRecv.String != "" {
			if t, err := time.Parse(time.RFC3339Nano, lastRecv.String); err == nil {
				es.LastReceivedAt = &t
			}
		}

		pKey := strings.ToLower(es.Portal)
		pPos, exists := portalIdx[pKey]
		if !exists {
			pPos = len(portals)
			portalIdx[pKey] = pPos
			portals = append(portals, PortalSummary{Portal: es.Portal})
		}

		eKey := pKey + "\x00" + strings.ToLower(es.Environment)
		ePos, eExists := envIdx[eKey]
		if !eExists {
			ePos = len(portals[pPos].Environments)
			envIdx[eKey] = ePos
			portals[pPos].Environments = append(portals[pPos].Environments, EnvironmentSummary{Environment: es.Environment})
		}

		p := &portals[pPos]
		env := &p.Environments[ePos]

		env.Endpoints = append(env.Endpoints, es)
		env.EndpointCount++
		p.EndpointCount++
		if es.Enabled {
			env.EnabledCount++
			p.EnabledCount++
		}
		env.EventCount += es.EventCount
		env.HeartbeatCount += es.HeartbeatCount
		env.ChallengeCount += es.ChallengeCount
		env.ErrorCount += es.ErrorCount
		env.LastReceivedAt = newerTime(env.LastReceivedAt, es.LastReceivedAt)

		p.EventCount += es.EventCount
		p.HeartbeatCount += es.HeartbeatCount
		p.ChallengeCount += es.ChallengeCount
		p.ErrorCount += es.ErrorCount
		p.LastReceivedAt = newerTime(p.LastReceivedAt, es.LastReceivedAt)
	}
	return portals, rows.Err()
}

func newerTime(a, b *time.Time) *time.Time {
	if b == nil {
		return a
	}
	if a == nil || b.After(*a) {
		t := *b
		return &t
	}
	return a
}

// GetEndpointBySlug returns an endpoint with decrypted secrets for webhook ingestion.
func (s *Store) GetEndpointBySlug(ctx context.Context, slug string) (Endpoint, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, portal, environment, name, slug, enabled, api_key_enc, hmac_secret_enc, hmac_required,
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
		SELECT id, portal, environment, name, slug, enabled, api_key_enc, hmac_secret_enc, hmac_required,
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
	if strings.TrimSpace(ep.Portal) == "" {
		ep.Portal = "Default"
	}
	if strings.TrimSpace(ep.Environment) == "" {
		ep.Environment = "Production"
	}
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
			portal, environment, name, slug, enabled, api_key_enc, hmac_secret_enc, hmac_required,
			custom_headers_json, pgp_private_key_enc, pgp_passphrase_enc,
			retention_days, heartbeat_retention_days, store_raw_on_error,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		ep.Portal, ep.Environment, ep.Name, ep.Slug, boolToInt(ep.Enabled), apiKeyEnc, hmacEnc, boolToInt(ep.HMACRequired),
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
	Portal                 string
	Environment            string
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

	if strings.TrimSpace(p.Portal) == "" {
		p.Portal = "Default"
	}
	if strings.TrimSpace(p.Environment) == "" {
		p.Environment = "Production"
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
		SET portal = ?, environment = ?, name = ?, slug = ?, enabled = ?,
		    api_key_enc = ?, hmac_secret_enc = ?, hmac_required = ?,
		    custom_headers_json = ?, pgp_private_key_enc = ?, pgp_passphrase_enc = ?,
		    retention_days = ?, heartbeat_retention_days = ?, store_raw_on_error = ?,
		    updated_at = ?
		WHERE id = ?
	`,
		p.Portal, p.Environment, p.Name, p.Slug, boolToInt(p.Enabled),
		apiKeyEnc, hmacEnc, boolToInt(p.HMACRequired),
		headersJSON, pgpKeyEnc, pgpPassEnc,
		p.RetentionDays, p.HeartbeatRetentionDays, boolToInt(p.StoreRawOnError),
		now, id,
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

	if p := strings.TrimSpace(f.Portal); p != "" {
		conds = append(conds, "lower(ep.portal) = lower(?)")
		args = append(args, p)
	}
	if env := strings.TrimSpace(f.Environment); env != "" {
		conds = append(conds, "lower(ep.environment) = lower(?)")
		args = append(args, env)
	}
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
		conds = append(conds, "(e.payload_json LIKE ? OR e.subscription_id LIKE ? OR e.session_id LIKE ? OR e.event_cases LIKE ? OR e.error_message LIKE ? OR ep.portal LIKE ? OR ep.environment LIKE ? OR ep.name LIKE ?)")
		args = append(args, like, like, like, like, like, like, like, like)
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	var total int64
	countSQL := `
		SELECT COUNT(*)
		FROM webhook_events e
		JOIN endpoints ep ON ep.id = e.endpoint_id
		` + where
	if err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	querySQL := `
		SELECT e.id, e.endpoint_id, ep.portal, ep.environment, ep.name, ep.slug,
		       e.received_at, e.kind, e.status_code,
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
		SELECT e.id, e.endpoint_id, ep.portal, ep.environment, ep.name, ep.slug,
		       e.received_at, e.kind, e.status_code,
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

// InsertAuditLog records an admin action with actor and timestamp.
func (s *Store) InsertAuditLog(ctx context.Context, entry AuditLog) error {
	if entry.OccurredAt.IsZero() {
		entry.OccurredAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_logs (
			occurred_at, actor_id, actor_email, action,
			target_type, target_id, target_label, details
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		entry.OccurredAt.UTC().Format(time.RFC3339Nano),
		entry.ActorID, entry.ActorEmail, entry.Action,
		entry.TargetType, entry.TargetID, entry.TargetLabel, entry.Details,
	)
	return err
}

// ListAuditLogs returns recent audit log entries matching filter criteria.
func (s *Store) ListAuditLogs(ctx context.Context, f AuditFilter) ([]AuditLog, int64, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	var conds []string
	var args []any
	if act := strings.TrimSpace(f.Action); act != "" {
		conds = append(conds, "a.action = ?")
		args = append(args, act)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + q + "%"
		conds = append(conds, "(COALESCE(u.display_name, '') LIKE ? OR a.actor_email LIKE ? OR a.actor_id LIKE ? OR a.action LIKE ? OR a.target_label LIKE ? OR a.details LIKE ?)")
		args = append(args, like, like, like, like, like, like)
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	var total int64
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM audit_logs a
		LEFT JOIN users u ON u.user_id = a.actor_id
	`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	qArgs := append(append([]any{}, args...), f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.occurred_at, a.actor_id, a.actor_email,
		       COALESCE(NULLIF(u.display_name, ''), NULLIF(a.actor_email, ''), NULLIF(u.email, ''), a.actor_id),
		       a.action, a.target_type, a.target_id, a.target_label, a.details
		FROM audit_logs a
		LEFT JOIN users u ON u.user_id = a.actor_id
		`+where+`
		ORDER BY a.occurred_at DESC, a.id DESC
		LIMIT ? OFFSET ?
	`, qArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []AuditLog
	for rows.Next() {
		var a AuditLog
		var occStr string
		if err := rows.Scan(&a.ID, &occStr, &a.ActorID, &a.ActorEmail, &a.ActorName, &a.Action, &a.TargetType, &a.TargetID, &a.TargetLabel, &a.Details); err != nil {
			return nil, 0, err
		}
		a.OccurredAt, _ = time.Parse(time.RFC3339Nano, occStr)
		items = append(items, a)
	}
	return items, total, rows.Err()
}

// UpsertUser records or refreshes an authenticated user's last seen timestamp and header-provided profile.
func (s *Store) UpsertUser(ctx context.Context, userID, email, displayName string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	email = strings.TrimSpace(email)
	displayName = strings.TrimSpace(displayName)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (user_id, email, display_name, synced_at, last_seen_at)
		VALUES (?, ?, ?, '', ?)
		ON CONFLICT(user_id) DO UPDATE SET
			email = CASE WHEN excluded.email != '' THEN excluded.email ELSE users.email END,
			display_name = CASE WHEN excluded.display_name != '' AND users.synced_at = '' THEN excluded.display_name ELSE users.display_name END,
			last_seen_at = excluded.last_seen_at
	`, userID, email, displayName, now)
	return err
}

// SyncUserFromAutentico stores read-only identity fields fetched from Autentico's API.
func (s *Store) SyncUserFromAutentico(ctx context.Context, userID, email, displayName string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	email = strings.TrimSpace(email)
	displayName = strings.TrimSpace(displayName)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (user_id, email, display_name, synced_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			email = CASE WHEN excluded.email != '' THEN excluded.email ELSE users.email END,
			display_name = excluded.display_name,
			synced_at = excluded.synced_at,
			last_seen_at = excluded.last_seen_at
	`, userID, email, displayName, now, now)
	return err
}

// GetUser returns a cached user profile by Autentico user ID.
func (s *Store) GetUser(ctx context.Context, userID string) (User, error) {
	var u User
	var syncedStr, seenStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, email, display_name, synced_at, last_seen_at
		FROM users
		WHERE user_id = ?
	`, userID).Scan(&u.UserID, &u.Email, &u.DisplayName, &syncedStr, &seenStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	if syncedStr != "" {
		u.SyncedAt, _ = time.Parse(time.RFC3339Nano, syncedStr)
	}
	u.LastSeenAt, _ = time.Parse(time.RFC3339Nano, seenStr)
	return u, nil
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
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs`).Scan(&st.AuditLogCount); err != nil {
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
		&ep.ID, &ep.Portal, &ep.Environment, &ep.Name, &ep.Slug, &enabledInt,
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
		&ev.ID, &ev.EndpointID, &ev.EndpointPortal, &ev.EndpointEnvironment, &ev.EndpointName, &ev.EndpointSlug,
		&receivedStr, &ev.Kind, &ev.StatusCode, &ev.ErrorMessage,
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
