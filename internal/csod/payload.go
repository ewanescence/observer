package csod

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Envelope mirrors the common CSOD webhook payload structure.
type Envelope struct {
	SubscriptionID string          `json:"subscriptionId"`
	SessionID      string          `json:"sessionId"`
	AttemptNumber  int             `json:"attemptNumber"`
	Records        json.RawMessage `json:"records"`
}

// DecodedPayload contains the decrypted, decompressed JSON and extracted metadata.
type DecodedPayload struct {
	JSONBytes      []byte
	SubscriptionID string
	SessionID      string
	AttemptNumber  int
	RecordCount    int
	IsHeartbeat    bool
	EventCases     []string
	WasEncrypted   bool
	WasCompressed  bool
	PGPKeyName     string
}

// DecodePayload runs CSOD's processing order:
// 1) OpenPGP decrypt (when x-content-encrypted: true)
// 2) Gunzip (when Content-Encoding or x-original-encoding is gzip, or gzip magic bytes)
// 3) Validate JSON and extract CSOD envelope metadata.
func DecodePayload(headers http.Header, rawBody []byte, pgpKeyArmored, pgpPassphrase string, maxDecompressedBytes int64) (DecodedPayload, error) {
	if len(rawBody) == 0 {
		return DecodedPayload{}, errors.New("empty request body")
	}
	if maxDecompressedBytes <= 0 {
		maxDecompressedBytes = 50 * 1024 * 1024
	}

	res := DecodedPayload{
		WasEncrypted: strings.EqualFold(strings.TrimSpace(headers.Get("x-content-encrypted")), "true"),
		PGPKeyName:   strings.TrimSpace(headers.Get("x-pgp-key-name")),
	}

	data := rawBody
	if res.WasEncrypted {
		if strings.TrimSpace(pgpKeyArmored) == "" {
			return res, errors.New("payload is PGP-encrypted but endpoint has no PGP private key configured")
		}
		decrypted, err := DecryptPGP(data, pgpKeyArmored, pgpPassphrase, maxDecompressedBytes)
		if err != nil {
			return res, err
		}
		data = decrypted
	}

	contentEnc := strings.ToLower(strings.TrimSpace(headers.Get("Content-Encoding")))
	origEnc := strings.ToLower(strings.TrimSpace(headers.Get("x-original-encoding")))
	if strings.Contains(contentEnc, "gzip") || strings.Contains(origEnc, "gzip") || isGzipMagic(data) {
		res.WasCompressed = true
		uncompressed, err := gunzipBytes(data, maxDecompressedBytes)
		if err != nil {
			return res, err
		}
		data = uncompressed
	}

	if !json.Valid(data) {
		return res, errors.New("decoded payload is not valid JSON")
	}

	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err == nil {
		res.JSONBytes = compact.Bytes()
	} else {
		res.JSONBytes = data
	}

	var env Envelope
	if err := json.Unmarshal(res.JSONBytes, &env); err == nil {
		res.SubscriptionID = env.SubscriptionID
		res.SessionID = env.SessionID
		res.AttemptNumber = env.AttemptNumber

		if len(env.Records) > 0 && string(env.Records) != "null" {
			var recs []struct {
				Value map[string]json.RawMessage `json:"value"`
			}
			if err := json.Unmarshal(env.Records, &recs); err == nil {
				res.RecordCount = len(recs)
				if res.RecordCount == 0 && res.SubscriptionID != "" {
					res.IsHeartbeat = true
				}
				caseSet := make(map[string]struct{})
				for _, rec := range recs {
					extractEventCases(rec.Value, caseSet)
				}
				for c := range caseSet {
					res.EventCases = append(res.EventCases, c)
				}
				sort.Strings(res.EventCases)
			}
		}
	}

	return res, nil
}

// DecryptPGP decrypts binary or ASCII-armored OpenPGP payloads using an ASCII-armored private key.
func DecryptPGP(encryptedBytes []byte, privateKeyArmored, passphrase string, maxOut int64) ([]byte, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(privateKeyArmored))
	if err != nil {
		return nil, fmt.Errorf("read PGP private key: %w", err)
	}
	if len(entityList) == 0 {
		return nil, errors.New("no PGP entities found in private key")
	}

	passBytes := []byte(passphrase)
	for _, entity := range entityList {
		if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
			if err := entity.PrivateKey.Decrypt(passBytes); err != nil {
				return nil, fmt.Errorf("decrypt PGP primary key: %w", err)
			}
		}
		for _, sub := range entity.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Decrypt(passBytes); err != nil {
					return nil, fmt.Errorf("decrypt PGP subkey: %w", err)
				}
			}
		}
	}

	var packetReader io.Reader = bytes.NewReader(encryptedBytes)
	trimmed := bytes.TrimSpace(encryptedBytes)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP MESSAGE-----")) {
		block, err := armor.Decode(bytes.NewReader(trimmed))
		if err != nil {
			return nil, fmt.Errorf("decode ASCII-armored PGP message: %w", err)
		}
		packetReader = block.Body
	}

	md, err := openpgp.ReadMessage(packetReader, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("read PGP message: %w", err)
	}

	limited := io.LimitReader(md.UnverifiedBody, maxOut+1)
	plain, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read PGP plaintext: %w", err)
	}
	if int64(len(plain)) > maxOut {
		return nil, fmt.Errorf("decrypted PGP payload exceeds %d byte limit", maxOut)
	}
	return plain, nil
}

func gunzipBytes(compressed []byte, maxOut int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer zr.Close()

	out, err := io.ReadAll(io.LimitReader(zr, maxOut+1))
	if err != nil {
		return nil, fmt.Errorf("decompress gzip stream: %w", err)
	}
	if int64(len(out)) > maxOut {
		return nil, fmt.Errorf("decompressed payload exceeds %d byte limit", maxOut)
	}
	return out, nil
}

func isGzipMagic(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

func extractEventCases(val map[string]json.RawMessage, out map[string]struct{}) {
	if len(val) == 0 {
		return
	}
	for _, caseField := range []string{"lmsEventsCase", "employeeEventsCase"} {
		if raw, ok := val[caseField]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil && s != "" {
				out[s] = struct{}{}
				return
			}
		}
	}
	for k := range val {
		if k == "headers" || strings.HasSuffix(k, "Case") {
			continue
		}
		out[k] = struct{}{}
	}
}
