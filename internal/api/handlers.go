package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/madhu/secret-service/internal/crypto"
	"github.com/madhu/secret-service/internal/store"
)

const (
	headerPassphrase    = "X-Passphrase"
	headerDeletionToken = "X-Deletion-Token"
)

type createRequest struct {
	Content    *string `json:"content"`
	TTLSeconds *int64  `json:"ttl_seconds"`
	MaxViews   *int    `json:"max_views"`
	Passphrase *string `json:"passphrase"`
}

type createResponse struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	DeletionToken string `json:"deletion_token"`
	ExpiresAt     string `json:"expires_at"`
	MaxViews      int    `json:"max_views"`
	Protected     bool   `json:"passphrase_protected"`
}

type readResponse struct {
	Content   string `json:"content"`
	Views     int    `json:"views"`
	MaxViews  int    `json:"max_views"`
	Remaining int    `json:"remaining"`
}

// POST /secrets
func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.allow(w, r, "create", ip, s.cfg.CreateBurst, s.cfg.CreateRate) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.MaxContentBytes)*2+4096)
	var req createRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "payload_too_large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_json"})
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_json", Detail: "trailing data"})
		return
	}

	if req.Content == nil || *req.Content == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request", Detail: "content is required"})
		return
	}
	if len(*req.Content) > s.cfg.MaxContentBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "payload_too_large", Detail: "content exceeds limit"})
		return
	}
	if !utf8.ValidString(*req.Content) {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request", Detail: "content must be valid UTF-8"})
		return
	}

	ttl := s.cfg.DefaultTTL
	if req.TTLSeconds != nil {
		ttl = time.Duration(*req.TTLSeconds) * time.Second
		if ttl < s.cfg.MinTTL || ttl > s.cfg.MaxTTL {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request", Detail: "ttl_seconds out of range"})
			return
		}
	}
	maxViews := 1
	if req.MaxViews != nil {
		maxViews = *req.MaxViews
		if maxViews < 1 || maxViews > s.cfg.MaxViewsLimit {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request", Detail: "max_views out of range"})
			return
		}
	}
	var passphrase []byte
	if req.Passphrase != nil && *req.Passphrase != "" {
		if len(*req.Passphrase) > s.cfg.MaxPassLen {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request", Detail: "passphrase too long"})
			return
		}
		passphrase = []byte(*req.Passphrase)
	}

	token := crypto.NewToken()
	deletionToken := crypto.NewDeletionToken()
	lookup, key := crypto.Derive(s.kek, token)
	defer crypto.Zero(key)

	plaintext := []byte(*req.Content)
	ciphertext, err := crypto.Seal(key, lookup, plaintext)
	crypto.Zero(plaintext)
	if err != nil {
		s.fail(w, r, "crypto.seal", err)
		return
	}

	rec := store.Record{
		Ciphertext:   ciphertext,
		MaxViews:     maxViews,
		ExpiresAt:    s.now().Add(ttl),
		DeletionHash: crypto.HashDeletionToken(deletionToken),
	}
	if passphrase != nil {
		salt := crypto.NewSalt()
		verifier, ok := s.stretch(r.Context(), key, salt, passphrase)
		crypto.Zero(passphrase)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "unavailable"})
			return
		}
		rec.PassSalt = salt
		rec.PassVerifier = verifier
	}

	if err := s.store.Put(r.Context(), lookup, rec); err != nil {
		s.fail(w, r, "store.put", err)
		return
	}

	s.metrics.created.Inc()
	s.log.Event("secret.created",
		"ref", ref(lookup), "ip", ip, "request_id", requestID(r),
		"ttl_seconds", int64(ttl.Seconds()), "max_views", maxViews, "protected", passphrase != nil,
	)
	writeJSON(w, http.StatusCreated, createResponse{
		ID:            token,
		URL:           s.baseURL(r) + "/s/" + token,
		DeletionToken: deletionToken,
		ExpiresAt:     rec.ExpiresAt.UTC().Format(time.RFC3339),
		MaxViews:      maxViews,
		Protected:     passphrase != nil,
	})
}

// GET /s/{id}
func (s *Server) handleRead(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		// Link previewers and prefetchers must never burn a view. HEAD is
		// answered identically whether or not the secret exists.
		w.WriteHeader(http.StatusOK)
		return
	}
	ip := s.clientIP(r)
	if !s.allow(w, r, "read", ip, s.cfg.ReadBurst, s.cfg.ReadRate) {
		return
	}

	id := r.PathValue("id")
	lookup, key := crypto.Derive(s.kek, id)
	defer crypto.Zero(key)

	// Passphrase handling. The amount of work depends only on whether the
	// header is present, never on whether the record exists.
	pass := store.PassNone
	if values := r.Header.Values(headerPassphrase); len(values) > 0 {
		supplied := []byte(values[0])
		salt, verifier, err := s.store.PassParams(r.Context(), lookup)
		if err != nil {
			s.fail(w, r, "store.passparams", err)
			return
		}
		if salt == nil {
			salt = crypto.DummySalt
		}
		got, ok := s.stretch(r.Context(), key, salt, supplied)
		crypto.Zero(supplied)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "unavailable"})
			return
		}
		if verifier != nil && crypto.Equal(got, verifier) {
			pass = store.PassOK
		} else {
			pass = store.PassBad
		}
	}

	res, err := s.store.Consume(r.Context(), lookup, s.now(), pass)
	if err != nil {
		s.fail(w, r, "store.consume", err)
		return
	}

	switch res.Outcome {
	case store.OutcomePassRequired:
		s.metrics.reads.WithLabelValues("passphrase_required").Inc()
		s.log.Event("secret.read_denied", "ref", ref(lookup), "ip", ip, "request_id", requestID(r), "reason", "passphrase_required")
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "passphrase_required"})
		return
	case store.OutcomePassWrong:
		reason := "passphrase_wrong"
		if res.Burned {
			reason = "burned"
			s.metrics.deleted.WithLabelValues("burned").Inc()
		}
		s.metrics.reads.WithLabelValues(reason).Inc()
		s.log.Event("secret.read_denied", "ref", ref(lookup), "ip", ip, "request_id", requestID(r), "reason", reason)
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
		return
	case store.OutcomeOK:
		// handled below
	default:
		s.metrics.reads.WithLabelValues("not_found").Inc()
		s.log.Event("secret.read_denied", "ref", ref(lookup), "ip", ip, "request_id", requestID(r), "reason", "not_found")
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
		return
	}

	plaintext, err := crypto.Open(key, lookup, res.Ciphertext)
	if err != nil {
		// The view was consumed but the record is unreadable (KEK mismatch or
		// tampering). Treat as gone.
		s.metrics.reads.WithLabelValues("undecryptable").Inc()
		s.log.Event("secret.read_denied", "ref", ref(lookup), "ip", ip, "request_id", requestID(r), "reason", "undecryptable")
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
		return
	}
	if res.Exhausted {
		s.metrics.deleted.WithLabelValues("exhausted").Inc()
	}
	s.metrics.reads.WithLabelValues("ok").Inc()
	s.log.Event("secret.viewed",
		"ref", ref(lookup), "ip", ip, "request_id", requestID(r),
		"views", res.Views, "max_views", res.MaxViews, "exhausted", res.Exhausted,
	)
	writeJSON(w, http.StatusOK, readResponse{
		Content:   string(plaintext),
		Views:     res.Views,
		MaxViews:  res.MaxViews,
		Remaining: res.MaxViews - res.Views,
	})
	crypto.Zero(plaintext)
}

// DELETE /s/{id}
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.allow(w, r, "delete", ip, s.cfg.ReadBurst, s.cfg.ReadRate) {
		return
	}
	token := r.Header.Get(headerDeletionToken)
	if token == "" {
		if rest, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			token = strings.TrimSpace(rest)
		}
	}
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "deletion_token_required"})
		return
	}

	lookup, key := crypto.Derive(s.kek, r.PathValue("id"))
	crypto.Zero(key)
	deleted, err := s.store.Delete(r.Context(), lookup, crypto.HashDeletionToken(token))
	if err != nil {
		s.fail(w, r, "store.delete", err)
		return
	}
	if !deleted {
		s.log.Event("secret.delete_denied", "ref", ref(lookup), "ip", ip, "request_id", requestID(r))
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
		return
	}
	s.metrics.deleted.WithLabelValues("revoked").Inc()
	s.log.Event("secret.deleted", "ref", ref(lookup), "ip", ip, "request_id", requestID(r))
	w.WriteHeader(http.StatusNoContent)
}

// GET /healthz
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "redis": "down"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, where string, err error) {
	s.log.Error(where, err, "request_id", requestID(r))
	writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "unavailable"})
}

// ref is the loggable reference for a record: a prefix of the one-way lookup
// id, which cannot be turned back into the share token.
func ref(lookup string) string {
	if len(lookup) > 8 {
		return lookup[:8]
	}
	return lookup
}
