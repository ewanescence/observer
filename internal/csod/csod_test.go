package csod

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func TestComputeTokenChallenge(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("test-secret-key"))
	got := ComputeTokenChallenge("POST", "/csod/webhook?a=1", "dbq2kjiql2c4", secret)
	if got == "" {
		t.Fatal("expected non-empty challenge hash")
	}
	// Deterministic check for same inputs
	got2 := ComputeTokenChallenge("post", "/csod/webhook?a=1", "dbq2kjiql2c4", secret)
	if got != got2 {
		t.Fatalf("expected method normalization to match: %s != %s", got, got2)
	}
}

func TestVerifyHMAC(t *testing.T) {
	body := []byte(`{"subscriptionId":"sub-1","records":[]}`)
	sum := sha256.Sum256(body)
	bodyHash := base64.StdEncoding.EncodeToString(sum[:])
	dateVal := "Fri, 03 May 2024 21:43:04 GMT"
	apiKey := "c90d4c31b21143b1b22f1addf2932536"
	secret := base64.StdEncoding.EncodeToString([]byte("shared-hmac-secret-bytes"))

	canonical := "POST\n/hooks/training?env=prod\n" + dateVal + ";" + bodyHash + ";customVal"
	sig := computeHMACBase64(canonical, secret)

	req := httptest.NewRequest(http.MethodPost, "/hooks/Training?Env=Prod", bytes.NewReader(body))
	req.Header.Set("Date", dateVal)
	req.Header.Set("x-content-sha256", bodyHash)
	req.Header.Set("x-csod-authentication", "customVal")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("Authorization", "HMAC-SHA256 Credential="+apiKey+"&SignedHeaders=Date;x-content-sha256;x-csod-authentication&Signature="+sig)

	if err := VerifyHMAC(req, body, secret, apiKey); err != nil {
		t.Fatalf("expected valid HMAC, got error: %v", err)
	}

	if err := VerifyHMAC(req, []byte("tampered"), secret, apiKey); err == nil {
		t.Fatal("expected error for tampered body")
	}
}

func TestDecodePayload_PGPAndGzip(t *testing.T) {
	entity, err := openpgp.NewEntity("CSOD Test", "", "csod@example.com", nil)
	if err != nil {
		t.Fatalf("new pgp entity: %v", err)
	}
	passphrase := "super-secret-pass"
	if err := entity.PrivateKey.Encrypt([]byte(passphrase)); err != nil {
		t.Fatalf("encrypt primary key: %v", err)
	}
	for _, sub := range entity.Subkeys {
		if sub.PrivateKey != nil {
			if err := sub.PrivateKey.Encrypt([]byte(passphrase)); err != nil {
				t.Fatalf("encrypt subkey: %v", err)
			}
		}
	}

	var privBuf bytes.Buffer
	armW, err := armor.Encode(&privBuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor encode: %v", err)
	}
	if err := entity.SerializePrivate(armW, nil); err != nil {
		t.Fatalf("serialize private key: %v", err)
	}
	_ = armW.Close()

	sampleJSON := `{"subscriptionId":"2f977027","sessionId":"37ae5176","attemptNumber":1,"records":[{"offset":168,"value":{"lmsEventsCase":"TrainingCompleted","trainingCompleted":{"data":{"trainingType":"CRSE"}}}}]}`

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, _ = zw.Write([]byte(sampleJSON))
	_ = zw.Close()

	var encBuf bytes.Buffer
	ptW, err := openpgp.Encrypt(&encBuf, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		t.Fatalf("openpgp encrypt: %v", err)
	}
	_, _ = io.Copy(ptW, &gzBuf)
	_ = ptW.Close()

	h := http.Header{}
	h.Set("Content-Type", "application/octet-stream")
	h.Set("x-content-encrypted", "true")
	h.Set("x-pgp-key-name", "my-key")
	h.Set("x-original-encoding", "gzip")

	decoded, err := DecodePayload(h, encBuf.Bytes(), privBuf.String(), passphrase, 1024*1024)
	if err != nil {
		t.Fatalf("DecodePayload failed: %v", err)
	}
	if !decoded.WasEncrypted || !decoded.WasCompressed {
		t.Fatalf("expected encrypted=true compressed=true, got %+v", decoded)
	}
	if decoded.SubscriptionID != "2f977027" || decoded.RecordCount != 1 || decoded.IsHeartbeat {
		t.Fatalf("unexpected envelope metadata: %+v", decoded)
	}
	if len(decoded.EventCases) != 1 || decoded.EventCases[0] != "TrainingCompleted" {
		t.Fatalf("unexpected event cases: %+v", decoded.EventCases)
	}
	if !strings.Contains(string(decoded.JSONBytes), `"trainingType":"CRSE"`) {
		t.Fatalf("unexpected JSON output: %s", string(decoded.JSONBytes))
	}
}

func TestDecodePayload_HeartbeatGzipOnly(t *testing.T) {
	hb := `{"subscriptionId":"sub-hb","sessionId":"sess-1","attemptNumber":1,"records":[]}`
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, _ = zw.Write([]byte(hb))
	_ = zw.Close()

	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Encoding", "gzip")

	decoded, err := DecodePayload(h, gzBuf.Bytes(), "", "", 1024*1024)
	if err != nil {
		t.Fatalf("DecodePayload failed: %v", err)
	}
	if !decoded.IsHeartbeat || decoded.RecordCount != 0 || decoded.WasEncrypted || !decoded.WasCompressed {
		t.Fatalf("unexpected heartbeat decode: %+v", decoded)
	}
}

func TestValidateCustomHeadersConfig(t *testing.T) {
	if err := ValidateCustomHeadersConfig(map[string]string{"x-csod-authentication": "abc_123,.-"}); err != nil {
		t.Fatalf("expected valid custom header, got %v", err)
	}
	if err := ValidateCustomHeadersConfig(map[string]string{"x-api-key": "123"}); err == nil {
		t.Fatal("expected x-api-key rejection")
	}
	if err := ValidateCustomHeadersConfig(map[string]string{"Authorization": "123"}); err == nil {
		t.Fatal("expected non-x- header rejection")
	}
}

func TestGeneratePGPKeyPair_AndDecryptRoundTrip(t *testing.T) {
	for _, pass := range []string{"", "pass-123"} {
		gen, err := GeneratePGPKeyPair("Observer Test", "test@example.com", pass, 2048)
		if err != nil {
			t.Fatalf("GeneratePGPKeyPair(pass=%q): %v", pass, err)
		}
		if !strings.Contains(gen.PublicKey, "BEGIN PGP PUBLIC KEY BLOCK") {
			t.Fatalf("missing armored public key")
		}
		if !strings.Contains(gen.PrivateKey, "BEGIN PGP PRIVATE KEY BLOCK") {
			t.Fatalf("missing armored private key")
		}

		pubEntities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(gen.PublicKey))
		if err != nil {
			t.Fatalf("read generated public key: %v", err)
		}

		payload := `{"subscriptionId":"sub-gen","sessionId":"sess-gen","attemptNumber":1,"records":[]}`
		var gzBuf bytes.Buffer
		zw := gzip.NewWriter(&gzBuf)
		_, _ = zw.Write([]byte(payload))
		_ = zw.Close()

		var encBuf bytes.Buffer
		ptW, err := openpgp.Encrypt(&encBuf, pubEntities, nil, nil, nil)
		if err != nil {
			t.Fatalf("encrypt with generated public key: %v", err)
		}
		_, _ = io.Copy(ptW, &gzBuf)
		_ = ptW.Close()

		h := http.Header{}
		h.Set("x-content-encrypted", "true")
		h.Set("x-original-encoding", "gzip")
		decoded, err := DecodePayload(h, encBuf.Bytes(), gen.PrivateKey, pass, 1024*1024)
		if err != nil {
			t.Fatalf("DecodePayload with generated key (pass=%q): %v", pass, err)
		}
		if !decoded.IsHeartbeat || decoded.SubscriptionID != "sub-gen" {
			t.Fatalf("unexpected decoded payload: %+v", decoded)
		}
	}
}
