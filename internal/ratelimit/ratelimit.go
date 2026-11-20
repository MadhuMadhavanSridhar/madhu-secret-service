// Package ratelimit is a per-client token bucket kept in Redis so every
// decision is atomic and shared across app instances.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter is a token bucket per (scope, client) pair.
type Limiter struct {
	rdb    redis.UniversalClient
	script *redis.Script
}

// New creates a Limiter.
func New(rdb redis.UniversalClient) *Limiter {
	return &Limiter{rdb: rdb, script: redis.NewScript(bucketLua)}
}

// Allow takes one token from the bucket for scope+client. When it refuses,
// retryAfter is the number of whole seconds until a token is available.
func (l *Limiter) Allow(ctx context.Context, scope, client string, burst int, ratePerSec float64) (allowed bool, retryAfter int, err error) {
	if burst <= 0 || ratePerSec <= 0 {
		return false, 0, errors.New("ratelimit: burst and rate must be positive")
	}
	key := "rl:" + scope + ":" + client
	ttlMs := int64(math.Ceil(float64(burst)/ratePerSec*1000)) + 1000
	now := time.Now().UnixMilli()
	raw, err := l.script.Run(ctx, l.rdb, []string{key}, burst, ratePerSec, now, ttlMs).Result()
	if err != nil {
		return false, 0, err
	}
	arr, ok := raw.([]interface{})
	if !ok || len(arr) != 2 {
		return false, 0, fmt.Errorf("ratelimit: unexpected reply %T", raw)
	}
	a, _ := arr[0].(int64)
	r, _ := arr[1].(int64)
	return a == 1, int(r), nil
}

// bucketLua: KEYS[1]=bucket, ARGV[1]=capacity, ARGV[2]=refill per second,
// ARGV[3]=now ms, ARGV[4]=ttl ms. Reply {allowed, retry_after_seconds}.
const bucketLua = `
local cap = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local b = redis.call('HMGET', KEYS[1], 't', 'ts')
local tokens = tonumber(b[1])
local ts = tonumber(b[2])
if tokens == nil or ts == nil then
  tokens = cap
  ts = now
end
local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
tokens = tokens + (elapsed / 1000) * rate
if tokens > cap then tokens = cap end
local allowed = 0
local retry = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry = math.ceil((1 - tokens) / rate)
  if retry < 1 then retry = 1 end
end
redis.call('HSET', KEYS[1], 't', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', KEYS[1], ttl)
return {allowed, retry}
`
