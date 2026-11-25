package csod

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var (
	customHeaderKeyRe   = regexp.MustCompile(`^[xX]-[a-zA-Z0-9-]{0,25}$`)
	customHeaderValueRe = regexp.MustCompile(`^[a-zA-Z0-9-_,.]{0,1000}$`)
)

// ValidateCustomHeadersConfig enforces CSOD's custom webhook header constraints:
// up to 4 pairs, x-* keys (excluding x-api-key), and allowed value characters.
func ValidateCustomHeadersConfig(headers map[string]string) error {
	if len(headers) > 4 {
		return errors.New("at most 4 custom headers are allowed by CSOD")
	}
	for k, v := range headers {
		if strings.EqualFold(k, "x-api-key") {
			return errors.New("x-api-key is managed separately and cannot be used as a custom header")
		}
		if !customHeaderKeyRe.MatchString(k) {
			return fmt.Errorf("custom header key %q must match ^[xX]-[a-zA-Z0-9-]{0,25}$", k)
		}
		if !customHeaderValueRe.MatchString(v) {
			return fmt.Errorf("custom header value for %q must match ^[a-zA-Z0-9-_,.]{0,1000}$", k)
		}
	}
	return nil
}

// VerifyAPIKey checks the incoming x-api-key header in constant time when configured.
func VerifyAPIKey(r *http.Request, expected string) error {
	if expected == "" {
		return nil
	}
	got := strings.TrimSpace(r.Header.Get("x-api-key"))
	if got == "" {
		return errors.New("missing x-api-key header")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		return errors.New("invalid x-api-key")
	}
	return nil
}

// VerifyCustomHeaders checks all configured custom x-* headers against the request.
func VerifyCustomHeaders(r *http.Request, expected map[string]string) error {
	for k, v := range expected {
		got := r.Header.Get(k)
		if subtle.ConstantTimeCompare([]byte(got), []byte(v)) != 1 {
			return fmt.Errorf("header %s mismatch", k)
		}
	}
	return nil
}

// ComputeTokenChallenge computes the Base64 HMAC-SHA256 response for CSOD's
// x-challenge-sha256 verification request:
// stringToSign = UPPER(method) + requestURI + challengeToken.
func ComputeTokenChallenge(method, requestURI, challengeToken, secret string) string {
	stringToSign := strings.ToUpper(method) + requestURI + challengeToken
	return computeHMACBase64(stringToSign, secret)
}

// VerifyHMAC validates CSOD's Authorization: HMAC-SHA256 header and x-content-sha256 body hash.
func VerifyHMAC(r *http.Request, rawBody []byte, secret, expectedAPIKey string) error {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return errors.New("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "HMAC-SHA256") {
		return errors.New("Authorization scheme must be HMAC-SHA256")
	}

	params := parseAuthParams(parts[1])
	credential := params["Credential"]
	signedHeadersRaw := params["SignedHeaders"]
	signature := params["Signature"]

	if signedHeadersRaw == "" || signature == "" {
		return errors.New("Authorization header missing SignedHeaders or Signature")
	}

	if expectedAPIKey != "" && credential != "" {
		if subtle.ConstantTimeCompare([]byte(credential), []byte(expectedAPIKey)) != 1 {
			return errors.New("Authorization Credential does not match endpoint API key")
		}
	}

	if contentHash := strings.TrimSpace(r.Header.Get("x-content-sha256")); contentHash != "" {
		sum := sha256.Sum256(rawBody)
		expectedBodyHash := base64.StdEncoding.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(contentHash), []byte(expectedBodyHash)) != 1 {
			return errors.New("x-content-sha256 body digest mismatch")
		}
	}

	signedHeaderNames := strings.Split(signedHeadersRaw, ";")
	signedValues := make([]string, 0, len(signedHeaderNames))
	for _, name := range signedHeaderNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if strings.EqualFold(name, "host") {
			signedValues = append(signedValues, r.Host)
		} else {
			signedValues = append(signedValues, r.Header.Get(name))
		}
	}

	reqURI := r.URL.RequestURI()
	canonical := strings.Join([]string{
		strings.ToUpper(r.Method),
		strings.ToLower(reqURI),
		strings.Join(signedValues, ";"),
	}, "\n")

	expectedSig := computeHMACBase64(canonical, secret)
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) != 1 {
		return errors.New("HMAC-SHA256 signature mismatch")
	}
	return nil
}

func parseAuthParams(raw string) map[string]string {
	out := make(map[string]string)
	for _, segment := range strings.Split(raw, "&") {
		kv := strings.SplitN(strings.TrimSpace(segment), "=", 2)
		if len(kv) == 2 {
			out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return out
}

func computeHMACBase64(stringToSign, secret string) string {
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil || len(key) == 0 {
		key = []byte(secret)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
