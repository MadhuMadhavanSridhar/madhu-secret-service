// Package api implements the HTTP surface described in DESIGN.md.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/madhu/secret-service/internal/audit"
	"github.com/madhu/secret-service/internal/crypto"
	"github.com/madhu/secret-service/internal/ratelimit"
	"github.com/madhu/secret-service/internal/store"
)

// Config tunes limits and network trust.
type Config struct {
	MaxContentBytes int
	DefaultTTL      time.Duration
	MinTTL          time.Duration
	MaxTTL          time.Duration
	MaxViewsLimit   int
	MaxPassLen      int

	CreateBurst int
	CreateRate  float64 // tokens per second
	ReadBurst   int
	ReadRate    float64

	TrustedProxies []*net.IPNet // peers allowed to set X-Forwarded-For
	ExemptCIDRs    []*net.IPNet // clients never rate limited (load generators)
	PublicBaseURL  string       // optional; otherwise derived from the request
}

// DefaultConfig returns the shipped defaults.
func DefaultConfig() Config {
	return Config{
		MaxContentBytes: 64 * 1024,
		DefaultTTL:      time.Hour,
		MinTTL:          time.Second,
		MaxTTL:          7 * 24 * time.Hour,
		MaxViewsLimit:   100,
		MaxPassLen:      256,
		CreateBurst:     30,
		CreateRate:      0.5, // 30 per minute sustained
		ReadBurst:       100,
		ReadRate:        4, // 240 per minute sustained
	}
}

// Server is the HTTP service.
type Server struct {
	cfg     Config
	kek     *crypto.KEK
	store   *store.Store
	limiter *ratelimit.Limiter
	log     *audit.Logger
	metrics *metrics
	kdfSem  chan struct{}
	now     func() time.Time
}

// New wires a Server.
func New(cfg Config, kek *crypto.KEK, st *store.Store, rl *ratelimit.Limiter, log *audit.Logger) *Server {
	return &Server{
		cfg:     cfg,
		kek:     kek,
		store:   st,
		limiter: rl,
		log:     log,
		metrics: newMetrics(),
		kdfSem:  make(chan struct{}, max(2, runtime.NumCPU())),
		now:     time.Now,
	}
}

// Handler returns the full middleware chain.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /secrets", s.handleCreate)
	mux.HandleFunc("GET /s/{id}", s.handleRead)
	mux.HandleFunc("DELETE /s/{id}", s.handleDelete)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("GET /metrics", s.metrics.handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
	})
	return s.observe(s.recover(securityHeaders(mux)))
}

// ---- middleware --------------------------------------------------------------

type ctxKey int

const requestIDKey ctxKey = 0

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// observe assigns a request id, records metrics and writes the access log
// entry using the matched route pattern, never the path.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		id := newRequestID()
		w.Header().Set("X-Request-Id", id)
		sw := &statusWriter{ResponseWriter: w}
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey, id))
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		dur := s.now().Sub(start)
		route := routeLabel(r.Pattern)
		s.metrics.requests.WithLabelValues(route, r.Method, strconv.Itoa(sw.status)).Inc()
		s.metrics.duration.WithLabelValues(route).Observe(dur.Seconds())
		s.log.Request(r.Method, route, sw.status, s.clientIP(r), id, dur)
	})
}

// routeLabel turns a ServeMux pattern such as "GET /s/{id}" into a bounded
// label. Unmatched requests and the catch-all collapse to "other".
func routeLabel(pattern string) string {
	_, path, found := strings.Cut(pattern, " ")
	if !found {
		path = pattern
	}
	if path == "" || path == "/" {
		return "other"
	}
	return path
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Event("http.panic", "request_id", requestID(r), "panic", strings.SplitN(toString(rec), "\n", 2)[0])
				writeJSON(w, http.StatusInternalServerError, errorBody{Error: "internal_error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// ---- helpers ---------------------------------------------------------------

type errorBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func newRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

func toString(v any) string {
	switch t := v.(type) {
	case error:
		return t.Error()
	case string:
		return t
	default:
		return "panic"
	}
}

// clientIP derives the client address. The TCP peer is authoritative. Only
// when the peer is a configured trusted proxy is X-Forwarded-For consulted,
// and then the rightmost address that is not itself a trusted proxy wins.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return host
	}
	if len(s.cfg.TrustedProxies) == 0 || !inAny(peer, s.cfg.TrustedProxies) {
		return peer.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for p := range strings.SplitSeq(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				hops = append(hops, p)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil {
			break
		}
		if !inAny(ip, s.cfg.TrustedProxies) {
			return ip.String()
		}
	}
	return peer.String()
}

func inAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// allow applies the rate limiter for scope. It writes the 429 itself and
// returns false when the request must stop. Redis failure fails closed.
func (s *Server) allow(w http.ResponseWriter, r *http.Request, scope, ip string, burst int, rate float64) bool {
	if parsed := net.ParseIP(ip); parsed != nil && inAny(parsed, s.cfg.ExemptCIDRs) {
		return true
	}
	ok, retry, err := s.limiter.Allow(r.Context(), scope, ip, burst, rate)
	if err != nil {
		s.log.Error("ratelimit.error", err, "request_id", requestID(r))
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "unavailable"})
		return false
	}
	if !ok {
		s.metrics.ratelimited.WithLabelValues(scope).Inc()
		s.log.Event("ratelimit.exceeded", "scope", scope, "ip", ip, "request_id", requestID(r))
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, http.StatusTooManyRequests, errorBody{Error: "rate_limited"})
		return false
	}
	return true
}

// stretch runs the passphrase KDF under a concurrency cap so a flood of
// passphrase attempts cannot exhaust memory.
func (s *Server) stretch(ctx context.Context, key, salt, pass []byte) ([]byte, bool) {
	select {
	case s.kdfSem <- struct{}{}:
	case <-ctx.Done():
		return nil, false
	}
	defer func() { <-s.kdfSem }()
	return crypto.PassVerifier(key, salt, pass), true
}

func (s *Server) baseURL(r *http.Request) string {
	if s.cfg.PublicBaseURL != "" {
		return strings.TrimRight(s.cfg.PublicBaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if len(s.cfg.TrustedProxies) > 0 {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if peer := net.ParseIP(host); peer != nil && inAny(peer, s.cfg.TrustedProxies) {
			if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
				scheme = "https"
			}
		}
	}
	return scheme + "://" + r.Host
}
