// Command server runs the one-time secret service.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/madhu/secret-service/internal/api"
	"github.com/madhu/secret-service/internal/audit"
	"github.com/madhu/secret-service/internal/crypto"
	"github.com/madhu/secret-service/internal/ratelimit"
	"github.com/madhu/secret-service/internal/store"
)

func main() {
	log := audit.New(os.Stdout)

	cfg, err := configFromEnv()
	if err != nil {
		log.Error("config", err)
		os.Exit(2)
	}
	maxFails := envInt("MAX_PASSPHRASE_FAILURES", 10)
	port := envStr("PORT", "8080")

	rdb := redis.NewClient(&redis.Options{
		Addr:         envStr("REDIS_ADDR", "127.0.0.1:6379"),
		Username:     envStr("REDIS_USERNAME", ""),
		Password:     envStr("REDIS_PASSWORD", ""),
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		PoolSize:     128,
		MinIdleConns: 8,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := waitForRedis(ctx, rdb); err != nil {
		log.Error("redis.connect", err)
		os.Exit(1)
	}

	// The KEK exists only in this process. A restart means a fresh KEK and,
	// because Redis is non-persistent, an empty store to go with it.
	kek := crypto.NewKEK()

	st := store.New(rdb, kek.Fingerprint(), maxFails)
	rl := ratelimit.New(rdb)
	srv := api.New(cfg, kek, st, rl, log)

	httpSrv := &http.Server{
		Addr:              ":" + port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	log.Event("server.started", "port", port, "kek_fingerprint", kek.Fingerprint())

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server.listen", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	_ = rdb.Close()
	log.Event("server.stopped")
}

func waitForRedis(ctx context.Context, rdb *redis.Client) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := rdb.Ping(ctx).Err(); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func configFromEnv() (api.Config, error) {
	cfg := api.DefaultConfig()
	cfg.MaxContentBytes = envInt("MAX_CONTENT_BYTES", cfg.MaxContentBytes)
	cfg.DefaultTTL = time.Duration(envInt("DEFAULT_TTL_SECONDS", int(cfg.DefaultTTL.Seconds()))) * time.Second
	cfg.MinTTL = time.Duration(envInt("MIN_TTL_SECONDS", int(cfg.MinTTL.Seconds()))) * time.Second
	cfg.MaxTTL = time.Duration(envInt("MAX_TTL_SECONDS", int(cfg.MaxTTL.Seconds()))) * time.Second
	cfg.MaxViewsLimit = envInt("MAX_VIEWS_LIMIT", cfg.MaxViewsLimit)
	cfg.PublicBaseURL = envStr("PUBLIC_BASE_URL", "")

	createPerMin := envInt("RATE_CREATE_PER_MIN", 30)
	readPerMin := envInt("RATE_READ_PER_MIN", 240)
	cfg.CreateBurst = envInt("RATE_CREATE_BURST", createPerMin)
	cfg.ReadBurst = envInt("RATE_READ_BURST", 100)
	cfg.CreateRate = float64(createPerMin) / 60
	cfg.ReadRate = float64(readPerMin) / 60

	var err error
	if cfg.TrustedProxies, err = parseCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS")); err != nil {
		return cfg, fmt.Errorf("TRUSTED_PROXY_CIDRS: %w", err)
	}
	if cfg.ExemptCIDRs, err = parseCIDRs(os.Getenv("RATE_LIMIT_EXEMPT_CIDRS")); err != nil {
		return cfg, fmt.Errorf("RATE_LIMIT_EXEMPT_CIDRS: %w", err)
	}
	if cfg.CreateBurst < 1 || cfg.ReadBurst < 1 || cfg.CreateRate <= 0 || cfg.ReadRate <= 0 {
		return cfg, errors.New("rate limits must be positive")
	}
	return cfg, nil
}

func parseCIDRs(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if strings.Contains(part, ":") {
				part += "/128"
			} else {
				part += "/32"
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func envStr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
