package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime settings loaded from environment variables.
type Config struct {
	ListenAddr             string
	DBPath                 string
	MasterKey              []byte
	TrustForwardAuth           bool
	AllowedUsers               map[string]struct{}
	AutenticoAppID             string
	AutenticoURL               string
	AutenticoAPIURL            string
	AutenticoAdminClientID     string
	AutenticoAdminClientSecret string
	AutenticoAdminUsername     string
	AutenticoAdminPassword     string
	AutenticoAdminToken        string
	AutenticoLogoutPath        string
	CentralLogoutURL           string
	RetentionDays          int
	HeartbeatRetentionDays int
	RetentionInterval      time.Duration
	MaxBodyBytes           int64
	MaxDecompressedBytes   int64
}

// Load parses configuration from environment variables with safe defaults.
func Load() (Config, error) {
	cfg := Config{
		ListenAddr:             envString("OBSERVER_LISTEN_ADDR", ":8080"),
		DBPath:                 envString("OBSERVER_DB_PATH", "/data/observer.db"),
		TrustForwardAuth:           envBool("OBSERVER_TRUST_FORWARD_AUTH", true),
		AutenticoAppID:             envString("OBSERVER_AUTENTICO_APP_ID", ""),
		AutenticoURL:               envString("OBSERVER_AUTENTICO_URL", ""),
		AutenticoAPIURL:            envString("OBSERVER_AUTENTICO_API_URL", ""),
		AutenticoAdminClientID:     envString("OBSERVER_AUTENTICO_ADMIN_CLIENT_ID", "autentico-admin"),
		AutenticoAdminClientSecret: envString("OBSERVER_AUTENTICO_ADMIN_CLIENT_SECRET", ""),
		AutenticoAdminUsername:     envString("OBSERVER_AUTENTICO_ADMIN_USERNAME", ""),
		AutenticoAdminPassword:     envString("OBSERVER_AUTENTICO_ADMIN_PASSWORD", ""),
		AutenticoAdminToken:        envString("OBSERVER_AUTENTICO_ADMIN_TOKEN", ""),
		AutenticoLogoutPath:        envString("OBSERVER_AUTENTICO_LOGOUT_PATH", ""),
		RetentionDays:          envInt("OBSERVER_RETENTION_DAYS", 30),
		HeartbeatRetentionDays: envInt("OBSERVER_HEARTBEAT_RETENTION_DAYS", 1),
		RetentionInterval:      envDuration("OBSERVER_RETENTION_INTERVAL", time.Hour),
		MaxBodyBytes:           envInt64("OBSERVER_MAX_BODY_BYTES", 10*1024*1024),
		MaxDecompressedBytes:   envInt64("OBSERVER_MAX_DECOMPRESSED_BYTES", 50*1024*1024),
		AllowedUsers:           make(map[string]struct{}),
	}

	if cfg.AutenticoLogoutPath == "" && cfg.AutenticoAppID != "" {
		cfg.AutenticoLogoutPath = "/_autentico/" + cfg.AutenticoAppID + "/logout"
	}
	if cfg.AutenticoURL != "" {
		cfg.CentralLogoutURL = strings.TrimRight(cfg.AutenticoURL, "/") + "/oauth2/logout"
	}
	if cfg.AutenticoAPIURL == "" {
		cfg.AutenticoAPIURL = cfg.AutenticoURL
	}

	if cfg.RetentionDays < 1 {
		return Config{}, errors.New("OBSERVER_RETENTION_DAYS must be >= 1")
	}
	if cfg.HeartbeatRetentionDays < 1 {
		return Config{}, errors.New("OBSERVER_HEARTBEAT_RETENTION_DAYS must be >= 1")
	}
	if cfg.RetentionInterval < time.Minute {
		return Config{}, errors.New("OBSERVER_RETENTION_INTERVAL must be >= 1m")
	}
	if cfg.MaxBodyBytes < 1024 {
		return Config{}, errors.New("OBSERVER_MAX_BODY_BYTES must be >= 1024")
	}

	if rawKey := strings.TrimSpace(os.Getenv("OBSERVER_MASTER_KEY")); rawKey != "" {
		key, err := decodeMasterKey(rawKey)
		if err != nil {
			return Config{}, err
		}
		cfg.MasterKey = key
	}

	if rawUsers := strings.TrimSpace(os.Getenv("OBSERVER_ALLOWED_USERS")); rawUsers != "" {
		for _, part := range strings.Split(rawUsers, ",") {
			u := strings.ToLower(strings.TrimSpace(part))
			if u != "" {
				cfg.AllowedUsers[u] = struct{}{}
			}
		}
	}

	return cfg, nil
}

func decodeMasterKey(raw string) ([]byte, error) {
	if len(raw) == 64 {
		if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("OBSERVER_MASTER_KEY must be a 32-byte key encoded as 64 hex chars or base64")
}

func envString(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envInt64(key string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
