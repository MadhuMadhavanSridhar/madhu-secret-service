package api

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics holds every exported series. Labels are bounded enumerations only:
// never a secret reference, never a client IP.
type metrics struct {
	reg         *prometheus.Registry
	requests    *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	created     prometheus.Counter
	reads       *prometheus.CounterVec
	deleted     *prometheus.CounterVec
	ratelimited *prometheus.CounterVec
}

func newMetrics() *metrics {
	m := &metrics{
		reg: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total", Help: "HTTP requests by route template, method and status.",
		}, []string{"route", "method", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Request latency by route template.",
			Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		}, []string{"route"}),
		created: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secrets_created_total", Help: "Secrets created.",
		}),
		reads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secret_reads_total", Help: "Read attempts by outcome.",
		}, []string{"outcome"}),
		deleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secrets_deleted_total", Help: "Deletions by reason.",
		}, []string{"reason"}),
		ratelimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ratelimit_rejections_total", Help: "Requests rejected by the rate limiter, by scope.",
		}, []string{"scope"}),
	}
	m.reg.MustRegister(m.requests, m.duration, m.created, m.reads, m.deleted, m.ratelimited)
	m.reg.MustRegister(collectors.NewGoCollector())
	return m
}

func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
