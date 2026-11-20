// Package audit writes structured JSON events to stdout.
//
// Rule: an event names who (client IP, request id), what (event name, secret
// reference) and when. It never carries secret content, passphrases, share
// tokens, deletion tokens, keys, or the request path (the path holds the key).
package audit

import (
	"io"
	"log/slog"
	"time"
)

// Logger emits audit events.
type Logger struct {
	l *slog.Logger
}

// New creates a JSON logger writing to w.
func New(w io.Writer) *Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	return &Logger{l: slog.New(h)}
}

// Event records an audit event.
func (a *Logger) Event(name string, attrs ...any) {
	a.l.Info(name, attrs...)
}

// Error records an operational error. Only err.Error() is logged, so callers
// must not wrap secrets into error strings.
func (a *Logger) Error(name string, err error, attrs ...any) {
	attrs = append(attrs, slog.String("error", err.Error()))
	a.l.Error(name, attrs...)
}

// Request records one completed HTTP request using its route template.
func (a *Logger) Request(method, route string, status int, ip, requestID string, dur time.Duration) {
	a.l.Info("http.request",
		slog.String("method", method),
		slog.String("route", route),
		slog.Int("status", status),
		slog.String("ip", ip),
		slog.String("request_id", requestID),
		slog.Int64("duration_ms", dur.Milliseconds()),
	)
}
