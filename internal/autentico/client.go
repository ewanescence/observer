package autentico

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// UserProfile holds read-only user identity fields retrieved from Autentico.
type UserProfile struct {
	ID          string
	Username    string
	Email       string
	DisplayName string
}

// Client queries Autentico's Admin API to resolve opaque ForwardAuth user IDs
// into readable usernames without manual entry in Observer.
type Client struct {
	apiURL       string
	clientID     string
	clientSecret string
	username     string
	password     string
	staticToken  string
	httpClient   *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewClient constructs an Autentico lookup client. If credentials are incomplete,
// Enabled() returns false and lookups become a no-op.
func NewClient(apiURL, clientID, clientSecret, username, password, staticToken string) *Client {
	return &Client{
		apiURL:       strings.TrimRight(strings.TrimSpace(apiURL), "/"),
		clientID:     strings.TrimSpace(clientID),
		clientSecret: strings.TrimSpace(clientSecret),
		username:     strings.TrimSpace(username),
		password:     strings.TrimSpace(password),
		staticToken:  strings.TrimSpace(staticToken),
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}
}

// Enabled reports whether Autentico Admin API lookups are configured.
func (c *Client) Enabled() bool {
	if c == nil || c.apiURL == "" {
		return false
	}
	return c.staticToken != "" || (c.username != "" && c.password != "")
}

// Summary returns a non-secret status string for startup logging.
func (c *Client) Summary() string {
	if !c.Enabled() {
		return "disabled"
	}
	if c.staticToken != "" {
		return fmt.Sprintf("enabled (url=%s, auth=static_token)", c.apiURL)
	}
	return fmt.Sprintf("enabled (url=%s, client_id=%s, username=%s)", c.apiURL, c.clientID, c.username)
}

// LookupUser fetches a user's profile from GET /admin/api/users/{id}.
func (c *Client) LookupUser(ctx context.Context, userID string) (UserProfile, error) {
	if !c.Enabled() {
		return UserProfile{}, errors.New("autentico lookup not configured")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return UserProfile{}, errors.New("empty userID")
	}

	tok, err := c.getToken(ctx, false)
	if err != nil {
		return UserProfile{}, err
	}

	prof, status, err := c.fetchUser(ctx, tok, userID)
	if status == http.StatusUnauthorized && c.staticToken == "" {
		tok, err = c.getToken(ctx, true)
		if err != nil {
			return UserProfile{}, err
		}
		prof, _, err = c.fetchUser(ctx, tok, userID)
	}
	return prof, err
}

func (c *Client) fetchUser(ctx context.Context, token, userID string) (UserProfile, int, error) {
	endpoint := c.apiURL + "/admin/api/users/" + url.PathEscape(userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return UserProfile{}, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return UserProfile{}, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodySnippet := readBodySnippet(resp.Body)
		return UserProfile{}, resp.StatusCode, fmt.Errorf("GET %s returned HTTP %d: %s", endpoint, resp.StatusCode, bodySnippet)
	}

	var envelope struct {
		Data struct {
			ID         string `json:"id"`
			Username   string `json:"username"`
			Email      string `json:"email"`
			GivenName  string `json:"given_name"`
			FamilyName string `json:"family_name"`
			Nickname   string `json:"nickname"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return UserProfile{}, resp.StatusCode, fmt.Errorf("decode autentico user: %w", err)
	}

	d := envelope.Data
	display := strings.TrimSpace(d.Username)
	if display == "" {
		display = strings.TrimSpace(strings.TrimSpace(d.GivenName) + " " + strings.TrimSpace(d.FamilyName))
	}
	if display == "" {
		display = strings.TrimSpace(d.Nickname)
	}
	if display == "" {
		display = strings.TrimSpace(d.Email)
	}

	return UserProfile{
		ID:          d.ID,
		Username:    strings.TrimSpace(d.Username),
		Email:       strings.TrimSpace(d.Email),
		DisplayName: display,
	}, resp.StatusCode, nil
}

func (c *Client) getToken(ctx context.Context, forceRefresh bool) (string, error) {
	if c.staticToken != "" {
		return c.staticToken, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !forceRefresh && c.token != "" && time.Now().Before(c.expiresAt) {
		return c.token, nil
	}

	tokResp, status, body, err := c.requestToken(ctx, false)
	if err != nil && c.clientID != "" && c.clientSecret != "" && (status == http.StatusUnauthorized || status == http.StatusBadRequest) {
		// Retry once with client_secret_post in case client uses form-post auth instead of Basic auth.
		tokResp2, status2, body2, err2 := c.requestToken(ctx, true)
		if err2 == nil {
			tokResp, status, body, err = tokResp2, status2, body2, nil
		} else {
			return "", fmt.Errorf("token request failed (basic HTTP %d: %s; post HTTP %d: %s)", status, body, status2, body2)
		}
	}
	if err != nil {
		return "", err
	}

	ttl := time.Duration(tokResp.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if ttl > time.Minute {
		ttl -= 30 * time.Second
	}
	c.token = tokResp.AccessToken
	c.expiresAt = time.Now().Add(ttl)
	return c.token, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func (c *Client) requestToken(ctx context.Context, useSecretPost bool) (tokenResponse, int, string, error) {
	form := url.Values{
		"grant_type": {"password"},
		"username":   {c.username},
		"password":   {c.password},
		"scope":      {"openid profile email"},
	}
	if c.clientID != "" {
		if c.clientSecret == "" {
			form.Set("client_id", c.clientID)
		} else if useSecretPost {
			form.Set("client_id", c.clientID)
			form.Set("client_secret", c.clientSecret)
		}
	}

	tokenURL := c.apiURL + "/oauth2/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.clientID != "" && c.clientSecret != "" && !useSecretPost {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return tokenResponse{}, 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet := readBodySnippet(resp.Body)
		return tokenResponse{}, resp.StatusCode, snippet, fmt.Errorf("POST %s returned HTTP %d: %s", tokenURL, resp.StatusCode, snippet)
	}

	var tokResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		return tokenResponse{}, resp.StatusCode, "", fmt.Errorf("decode autentico token: %w", err)
	}
	if tokResp.AccessToken == "" {
		return tokenResponse{}, resp.StatusCode, "", errors.New("autentico returned empty access_token")
	}
	return tokResp, resp.StatusCode, "", nil
}

func readBodySnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	return strings.TrimSpace(string(b))
}
