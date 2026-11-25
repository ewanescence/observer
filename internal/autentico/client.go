package autentico

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
// into readable names/usernames without manual entry in Observer.
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
		return UserProfile{}, resp.StatusCode, fmt.Errorf("autentico user lookup returned HTTP %d", resp.StatusCode)
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

	form := url.Values{
		"grant_type": {"password"},
		"username":   {c.username},
		"password":   {c.password},
		"scope":      {"openid profile email"},
	}
	if c.clientID != "" && c.clientSecret == "" {
		form.Set("client_id", c.clientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.clientID != "" && c.clientSecret != "" {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("autentico token request failed with HTTP %d", resp.StatusCode)
	}

	var tokResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		return "", fmt.Errorf("decode autentico token: %w", err)
	}
	if tokResp.AccessToken == "" {
		return "", errors.New("autentico returned empty access_token")
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
