package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/elematte/observer/internal/csod"
	"github.com/elematte/observer/internal/db"
)

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		writeJSONError(w, http.StatusNotFound, "endpoint not found")
		return
	}

	ep, err := s.store.GetEndpointBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "endpoint not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !ep.Enabled {
		writeJSONError(w, http.StatusNotFound, "endpoint disabled")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.recordIngestError(r, ep.ID, http.StatusRequestEntityTooLarge, "request body exceeds size limit", nil)
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		s.recordIngestError(r, ep.ID, http.StatusBadRequest, "failed reading request body: "+err.Error(), nil)
		writeJSONError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	headersJSON := sanitizeHeadersJSON(r.Header)

	if err := csod.VerifyAPIKey(r, ep.APIKey); err != nil {
		s.recordIngestError(r, ep.ID, http.StatusUnauthorized, err.Error(), rawBody)
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if err := csod.VerifyCustomHeaders(r, ep.CustomHeaders); err != nil {
		s.recordIngestError(r, ep.ID, http.StatusUnauthorized, err.Error(), rawBody)
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// CSOD Token Challenge Verification (endpoint creation / URL update)
	if challenge := strings.TrimSpace(r.Header.Get("x-challenge-sha256")); challenge != "" {
		if ep.HMACSecret == "" {
			msg := "received x-challenge-sha256 but endpoint has no HMAC secret configured"
			s.recordIngestError(r, ep.ID, http.StatusBadRequest, msg, rawBody)
			writeJSONError(w, http.StatusBadRequest, msg)
			return
		}
		sig := csod.ComputeTokenChallenge(r.Method, r.URL.RequestURI(), challenge, ep.HMACSecret)
		_, _ = s.store.InsertEvent(r.Context(), db.WebhookEvent{
			EndpointID:   ep.ID,
			Kind:         "challenge",
			StatusCode:   http.StatusOK,
			HeadersJSON:  headersJSON,
			PayloadJSON:  `{"challenge":"verified"}`,
			RawSizeBytes: len(rawBody),
		})
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("x-challenge-sha256", sig)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"verified"}`))
		return
	}

	// Standard CSOD HMAC-SHA256 verification
	hasHMACAuth := strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Authorization"))), "hmac-sha256 ")
	if ep.HMACRequired || hasHMACAuth {
		if ep.HMACSecret == "" {
			msg := "HMAC verification required but endpoint has no HMAC secret configured"
			s.recordIngestError(r, ep.ID, http.StatusUnauthorized, msg, rawBody)
			writeJSONError(w, http.StatusUnauthorized, msg)
			return
		}
		if err := csod.VerifyHMAC(r, rawBody, ep.HMACSecret, ep.APIKey); err != nil {
			s.recordIngestError(r, ep.ID, http.StatusUnauthorized, err.Error(), rawBody)
			writeJSONError(w, http.StatusUnauthorized, err.Error())
			return
		}
	}

	decoded, err := csod.DecodePayload(r.Header, rawBody, ep.PGPPrivateKey, ep.PGPPassphrase, s.cfg.MaxDecompressedBytes)
	if err != nil {
		respStatus := http.StatusInternalServerError
		if ep.StoreRawOnError {
			respStatus = http.StatusOK
		}
		_, _ = s.store.InsertEvent(r.Context(), db.WebhookEvent{
			EndpointID:    ep.ID,
			Kind:          "error",
			StatusCode:    respStatus,
			ErrorMessage:  err.Error(),
			WasEncrypted:  decoded.WasEncrypted,
			WasCompressed: decoded.WasCompressed,
			PGPKeyName:    decoded.PGPKeyName,
			HeadersJSON:   headersJSON,
			RawSizeBytes:  len(rawBody),
		})
		if ep.StoreRawOnError {
			writeJSON(w, http.StatusOK, map[string]string{"status": "stored_with_error"})
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "payload decode failed: "+err.Error())
		return
	}

	kind := "event"
	if decoded.IsHeartbeat {
		kind = "heartbeat"
	}

	_, err = s.store.InsertEvent(r.Context(), db.WebhookEvent{
		EndpointID:       ep.ID,
		Kind:             kind,
		StatusCode:       http.StatusOK,
		SubscriptionID:   decoded.SubscriptionID,
		SessionID:        decoded.SessionID,
		AttemptNumber:    decoded.AttemptNumber,
		RecordCount:      decoded.RecordCount,
		EventCases:       strings.Join(decoded.EventCases, ", "),
		WasEncrypted:     decoded.WasEncrypted,
		WasCompressed:    decoded.WasCompressed,
		PGPKeyName:       decoded.PGPKeyName,
		HeadersJSON:      headersJSON,
		PayloadJSON:      string(decoded.JSONBytes),
		RawSizeBytes:     len(rawBody),
		DecodedSizeBytes: len(decoded.JSONBytes),
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to persist event")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) recordIngestError(r *http.Request, endpointID int64, statusCode int, msg string, rawBody []byte) {
	_, _ = s.store.InsertEvent(r.Context(), db.WebhookEvent{
		EndpointID:   endpointID,
		Kind:         "error",
		StatusCode:   statusCode,
		ErrorMessage: msg,
		HeadersJSON:  sanitizeHeadersJSON(r.Header),
		RawSizeBytes: len(rawBody),
	})
}

func sanitizeHeadersJSON(h http.Header) string {
	clean := make(map[string]string, len(h))
	for k, vals := range h {
		joined := strings.Join(vals, ", ")
		if strings.EqualFold(k, "x-api-key") {
			joined = maskSecretPreview(joined)
		}
		clean[k] = joined
	}
	b, err := json.Marshal(clean)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func maskSecretPreview(v string) string {
	if len(v) <= 8 {
		return "****"
	}
	return v[:4] + "****" + v[len(v)-4:]
}
