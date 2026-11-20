// Package store persists encrypted secrets in Redis.
//
// Every state transition that decides whether a caller may see content
// (expiry, passphrase outcome, view counting, deletion) runs inside one Lua
// script. Redis executes scripts serially, so fifty racing reads of a
// one-view secret yield exactly one success without any lock in the app.
package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Outcome of a consume attempt.
type Outcome int

const (
	OutcomeNotFound     Outcome = 0
	OutcomeOK           Outcome = 1
	OutcomePassRequired Outcome = 2
	OutcomePassWrong    Outcome = 3
)

// PassState tells the consume script what the app concluded about the
// passphrase the caller supplied.
type PassState string

const (
	PassNone PassState = "none" // no passphrase header on the request
	PassOK   PassState = "ok"
	PassBad  PassState = "bad"
)

// Record is what gets written for a new secret.
type Record struct {
	Ciphertext   []byte
	MaxViews     int
	ExpiresAt    time.Time
	DeletionHash string
	PassSalt     []byte // nil when unprotected
	PassVerifier []byte // nil when unprotected
}

// ConsumeResult describes what the script decided.
type ConsumeResult struct {
	Outcome    Outcome
	Ciphertext []byte
	Views      int
	MaxViews   int
	Exhausted  bool // this read was the last allowed one; record deleted
	Burned     bool // too many wrong passphrases; record deleted
}

// Store wraps a Redis client with the service's scripts.
type Store struct {
	rdb      redis.UniversalClient
	prefix   string
	maxFails int
	consume  *redis.Script
	del      *redis.Script
}

// New creates a Store. kekFingerprint namespaces every record so that a
// restarted process (fresh KEK) never serves records it cannot decrypt.
func New(rdb redis.UniversalClient, kekFingerprint string, maxFails int) *Store {
	return &Store{
		rdb:      rdb,
		prefix:   "s:" + kekFingerprint + ":",
		maxFails: maxFails,
		consume:  redis.NewScript(consumeLua),
		del:      redis.NewScript(deleteLua),
	}
}

func (s *Store) key(lookup string) string { return s.prefix + lookup }

// Put stores a new record with its TTL.
func (s *Store) Put(ctx context.Context, lookup string, rec Record) error {
	k := s.key(lookup)
	fields := map[string]interface{}{
		"ct":  rec.Ciphertext,
		"v":   0,
		"mv":  rec.MaxViews,
		"exp": rec.ExpiresAt.Unix(),
		"dt":  rec.DeletionHash,
		"pf":  0,
		"c":   time.Now().Unix(),
	}
	if rec.PassVerifier != nil {
		fields["ps"] = rec.PassSalt
		fields["pv"] = rec.PassVerifier
	}
	pipe := s.rdb.TxPipeline()
	pipe.HSet(ctx, k, fields)
	pipe.ExpireAt(ctx, k, rec.ExpiresAt)
	_, err := pipe.Exec(ctx)
	return err
}

// PassParams returns the passphrase salt and verifier for a record. Both are
// nil when the record is missing or unprotected.
func (s *Store) PassParams(ctx context.Context, lookup string) (salt, verifier []byte, err error) {
	vals, err := s.rdb.HMGet(ctx, s.key(lookup), "ps", "pv").Result()
	if err != nil {
		return nil, nil, err
	}
	if len(vals) != 2 || vals[0] == nil || vals[1] == nil {
		return nil, nil, nil
	}
	ps, ok1 := vals[0].(string)
	pv, ok2 := vals[1].(string)
	if !ok1 || !ok2 {
		return nil, nil, errors.New("store: unexpected passphrase field types")
	}
	return []byte(ps), []byte(pv), nil
}

// Consume atomically applies one read attempt.
func (s *Store) Consume(ctx context.Context, lookup string, now time.Time, pass PassState) (ConsumeResult, error) {
	raw, err := s.consume.Run(ctx, s.rdb, []string{s.key(lookup)}, now.Unix(), string(pass), s.maxFails).Result()
	if err != nil {
		return ConsumeResult{}, err
	}
	arr, ok := raw.([]interface{})
	if !ok || len(arr) == 0 {
		return ConsumeResult{}, fmt.Errorf("store: unexpected script reply %T", raw)
	}
	code, err := asInt(arr[0])
	if err != nil {
		return ConsumeResult{}, err
	}
	res := ConsumeResult{Outcome: Outcome(code)}
	switch res.Outcome {
	case OutcomeOK:
		if len(arr) != 5 {
			return ConsumeResult{}, errors.New("store: malformed ok reply")
		}
		ct, _ := arr[1].(string)
		res.Ciphertext = []byte(ct)
		if res.Views, err = asInt(arr[2]); err != nil {
			return ConsumeResult{}, err
		}
		if res.MaxViews, err = asInt(arr[3]); err != nil {
			return ConsumeResult{}, err
		}
		last, err := asInt(arr[4])
		if err != nil {
			return ConsumeResult{}, err
		}
		res.Exhausted = last == 1
	case OutcomePassWrong:
		if len(arr) == 2 {
			b, _ := asInt(arr[1])
			res.Burned = b == 1
		}
	}
	return res, nil
}

// Delete removes a record if the deletion token hash matches. Returns true
// when a record was deleted.
func (s *Store) Delete(ctx context.Context, lookup, deletionHash string) (bool, error) {
	n, err := s.del.Run(ctx, s.rdb, []string{s.key(lookup)}, deletionHash).Int()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Ping checks Redis liveness.
func (s *Store) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

func asInt(v interface{}) (int, error) {
	switch t := v.(type) {
	case int64:
		return int(t), nil
	case string:
		return strconv.Atoi(t)
	default:
		return 0, fmt.Errorf("store: unexpected reply element %T", v)
	}
}

// consumeLua: KEYS[1]=record, ARGV[1]=now (unix s), ARGV[2]=pass state, ARGV[3]=max fails.
// Replies: {0} not found/expired, {2} passphrase required,
// {3, burned} wrong passphrase, {1, ct, views, max_views, last} success.
const consumeLua = `
local k = KEYS[1]
local now = tonumber(ARGV[1])
local pass = ARGV[2]
local maxfails = tonumber(ARGV[3])
local r = redis.call('HMGET', k, 'exp', 'mv', 'pv')
if not r[1] then return {0} end
if tonumber(r[1]) <= now then
  redis.call('DEL', k)
  return {0}
end
if r[3] then
  if pass == 'none' then return {2} end
  if pass ~= 'ok' then
    local f = redis.call('HINCRBY', k, 'pf', 1)
    if f >= maxfails then
      redis.call('DEL', k)
      return {3, 1}
    end
    return {3, 0}
  end
end
local mv = tonumber(r[2])
local v = redis.call('HINCRBY', k, 'v', 1)
if v > mv then
  redis.call('DEL', k)
  return {0}
end
local ct = redis.call('HGET', k, 'ct')
local last = 0
if v >= mv then
  redis.call('DEL', k)
  last = 1
end
return {1, ct, v, mv, last}
`

// deleteLua: KEYS[1]=record, ARGV[1]=sha256 hex of the presented deletion token.
const deleteLua = `
local h = redis.call('HGET', KEYS[1], 'dt')
if h and h == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
`
