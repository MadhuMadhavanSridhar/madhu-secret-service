package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/madhu/secret-service/internal/audit"
	"github.com/madhu/secret-service/internal/crypto"
	"github.com/madhu/secret-service/internal/ratelimit"
	"github.com/madhu/secret-service/internal/store"
)

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fixture struct {
	ts   *httptest.Server
	mr   *miniredis.Miniredis
	logs *safeBuf
	srv  *Server
	now  time.Time
	mu   sync.Mutex
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func newFixture(t *testing.T, mut func(*Config)) *fixture {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cfg := DefaultConfig()
	if mut != nil {
		mut(&cfg)
	}
	kek := crypto.NewKEK()
	logs := &safeBuf{}
	srv := New(cfg, kek, store.New(rdb, kek.Fingerprint(), 3), ratelimit.New(rdb), audit.New(logs))
	f := &fixture{mr: mr, logs: logs, srv: srv, now: time.Now()}
	srv.now = func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
	f.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(f.ts.Close)
	return f
}

type created struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	DeletionToken string `json:"deletion_token"`
	MaxViews      int    `json:"max_views"`
}

func (f *fixture) do(t *testing.T, method, path string, body string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := f.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (f *fixture) create(t *testing.T, body string) created {
	t.Helper()
	resp, b := f.do(t, http.MethodPost, "/secrets", body, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d body %s", resp.StatusCode, b)
	}
	var c created
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCreateReadOnce(t *testing.T) {
	f := newFixture(t, nil)
	c := f.create(t, `{"content":"hello world"}`)
	if len(c.ID) != 43 || !strings.HasSuffix(c.URL, "/s/"+c.ID) || len(c.DeletionToken) != 43 {
		t.Fatalf("unexpected create response %+v", c)
	}

	resp, b := f.do(t, http.MethodGet, "/s/"+c.ID, "", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"content":"hello world"`) {
		t.Fatalf("first read: %d %s", resp.StatusCode, b)
	}
	if !strings.Contains(string(b), `"remaining":0`) {
		t.Fatalf("expected remaining 0, got %s", b)
	}
	resp, b = f.do(t, http.MethodGet, "/s/"+c.ID, "", nil)
	if resp.StatusCode != 404 || string(bytes.TrimSpace(b)) != `{"error":"not_found"}` {
		t.Fatalf("second read: %d %s", resp.StatusCode, b)
	}
}

func TestMaxViews(t *testing.T) {
	f := newFixture(t, nil)
	c := f.create(t, `{"content":"x","max_views":3}`)
	for i := 1; i <= 3; i++ {
		resp, b := f.do(t, http.MethodGet, "/s/"+c.ID, "", nil)
		if resp.StatusCode != 200 {
			t.Fatalf("read %d: %d %s", i, resp.StatusCode, b)
		}
	}
	resp, _ := f.do(t, http.MethodGet, "/s/"+c.ID, "", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("fourth read should be 404, got %d", resp.StatusCode)
	}
}

func TestViewOnceUnderRace(t *testing.T) {
	f := newFixture(t, nil)
	c := f.create(t, `{"content":"race"}`)
	const n = 50
	var wg sync.WaitGroup
	codes := make(chan int, n)
	start := make(chan struct{})
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: n}}
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := client.Get(f.ts.URL + "/s/" + c.ID)
			if err != nil {
				codes <- -1
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	close(start)
	wg.Wait()
	close(codes)
	ok, nf, other := 0, 0, 0
	for code := range codes {
		switch code {
		case 200:
			ok++
		case 404:
			nf++
		default:
			other++
		}
	}
	if ok != 1 || nf != n-1 || other != 0 {
		t.Fatalf("race: ok=%d notfound=%d other=%d", ok, nf, other)
	}
}

func TestPassphrase(t *testing.T) {
	f := newFixture(t, nil)
	c := f.create(t, `{"content":"guarded","passphrase":"open sesame"}`)

	resp, b := f.do(t, http.MethodGet, "/s/"+c.ID, "", nil)
	if resp.StatusCode != 401 || !strings.Contains(string(b), "passphrase_required") {
		t.Fatalf("no passphrase: %d %s", resp.StatusCode, b)
	}
	resp, b = f.do(t, http.MethodGet, "/s/"+c.ID, "", map[string]string{"X-Passphrase": "wrong"})
	if resp.StatusCode != 404 || string(bytes.TrimSpace(b)) != `{"error":"not_found"}` {
		t.Fatalf("wrong passphrase must look like not found: %d %s", resp.StatusCode, b)
	}
	resp, b = f.do(t, http.MethodGet, "/s/"+c.ID, "", map[string]string{"X-Passphrase": "open sesame"})
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"content":"guarded"`) {
		t.Fatalf("right passphrase: %d %s", resp.StatusCode, b)
	}

	// Lockout after the configured number of failures (3 in the fixture).
	c = f.create(t, `{"content":"burn me","passphrase":"pw"}`)
	for i := 0; i < 3; i++ {
		f.do(t, http.MethodGet, "/s/"+c.ID, "", map[string]string{"X-Passphrase": "nope"})
	}
	resp, _ = f.do(t, http.MethodGet, "/s/"+c.ID, "", map[string]string{"X-Passphrase": "pw"})
	if resp.StatusCode != 404 {
		t.Fatalf("expected burned secret to be gone, got %d", resp.StatusCode)
	}
	if !strings.Contains(f.logs.String(), `"reason":"burned"`) {
		t.Fatal("expected a burned audit event")
	}
}

func TestDelete(t *testing.T) {
	f := newFixture(t, nil)
	c := f.create(t, `{"content":"revoke me"}`)

	resp, _ := f.do(t, http.MethodDelete, "/s/"+c.ID, "", nil)
	if resp.StatusCode != 401 {
		t.Fatalf("missing token: %d", resp.StatusCode)
	}
	resp, _ = f.do(t, http.MethodDelete, "/s/"+c.ID, "", map[string]string{"X-Deletion-Token": "nope"})
	if resp.StatusCode != 404 {
		t.Fatalf("wrong token: %d", resp.StatusCode)
	}
	resp, _ = f.do(t, http.MethodDelete, "/s/"+c.ID, "", map[string]string{"Authorization": "Bearer " + c.DeletionToken})
	if resp.StatusCode != 204 {
		t.Fatalf("right token: %d", resp.StatusCode)
	}
	resp, _ = f.do(t, http.MethodGet, "/s/"+c.ID, "", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("read after revoke: %d", resp.StatusCode)
	}
	resp, _ = f.do(t, http.MethodDelete, "/s/"+c.ID, "", map[string]string{"X-Deletion-Token": c.DeletionToken})
	if resp.StatusCode != 404 {
		t.Fatalf("second delete: %d", resp.StatusCode)
	}
}

func TestTTLExpiry(t *testing.T) {
	f := newFixture(t, nil)
	c := f.create(t, `{"content":"brief","ttl_seconds":5}`)
	f.advance(6 * time.Second)
	resp, _ := f.do(t, http.MethodGet, "/s/"+c.ID, "", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expired secret readable: %d", resp.StatusCode)
	}
}

func TestNoPlaintextAtRestOrInLogs(t *testing.T) {
	f := newFixture(t, nil)
	const canary = "CANARY-7f3a9c-DO-NOT-LEAK"
	const pass = "PASSPHRASE-b81e2d"
	c := f.create(t, `{"content":"`+canary+`","passphrase":"`+pass+`","max_views":2}`)

	for _, k := range f.mr.Keys() {
		var blob strings.Builder
		blob.WriteString(k)
		if f.mr.Type(k) == "hash" {
			fields, _ := f.mr.HKeys(k)
			for _, field := range fields {
				blob.WriteString(f.mr.HGet(k, field))
			}
		} else {
			v, _ := f.mr.Get(k)
			blob.WriteString(v)
		}
		for _, s := range []string{canary, pass, c.ID, c.DeletionToken} {
			if strings.Contains(blob.String(), s) {
				t.Fatalf("redis key %q contains %q", k, s)
			}
		}
	}

	f.do(t, http.MethodGet, "/s/"+c.ID, "", map[string]string{"X-Passphrase": "wrong"})
	f.do(t, http.MethodGet, "/s/"+c.ID, "", map[string]string{"X-Passphrase": pass})
	f.do(t, http.MethodDelete, "/s/"+c.ID, "", map[string]string{"X-Deletion-Token": c.DeletionToken})

	logs := f.logs.String()
	for _, s := range []string{canary, pass, c.ID, c.DeletionToken, "/s/" + c.ID} {
		if strings.Contains(logs, s) {
			t.Fatalf("audit log contains %q", s)
		}
	}
	for _, want := range []string{"secret.created", "secret.viewed", "secret.deleted", `"route":"/s/{id}"`} {
		if !strings.Contains(logs, want) {
			t.Fatalf("audit log missing %q", want)
		}
	}
}

func TestRateLimitAndSpoofedForwardedFor(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.CreateBurst = 5; c.CreateRate = 0.01 })
	for i := 0; i < 5; i++ {
		resp, _ := f.do(t, http.MethodPost, "/secrets", `{"content":"x"}`, map[string]string{"X-Forwarded-For": "10.0.0." + string(rune('1'+i))})
		if resp.StatusCode != 201 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ := f.do(t, http.MethodPost, "/secrets", `{"content":"x"}`, map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After, got %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

func TestForwardedForHonouredOnlyFromTrustedProxy(t *testing.T) {
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	f := newFixture(t, func(c *Config) {
		c.CreateBurst = 2
		c.CreateRate = 0.01
		c.TrustedProxies = []*net.IPNet{lo}
	})
	for _, ip := range []string{"198.51.100.1", "198.51.100.1", "198.51.100.2", "198.51.100.2"} {
		resp, _ := f.do(t, http.MethodPost, "/secrets", `{"content":"x"}`, map[string]string{"X-Forwarded-For": ip})
		if resp.StatusCode != 201 {
			t.Fatalf("ip %s: %d", ip, resp.StatusCode)
		}
	}
	resp, _ := f.do(t, http.MethodPost, "/secrets", `{"content":"x"}`, map[string]string{"X-Forwarded-For": "198.51.100.1"})
	if resp.StatusCode != 429 {
		t.Fatalf("expected per-forwarded-ip bucket to be exhausted, got %d", resp.StatusCode)
	}
}

func TestExemptCIDRSkipsLimiter(t *testing.T) {
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	f := newFixture(t, func(c *Config) { c.CreateBurst = 1; c.CreateRate = 0.01; c.ExemptCIDRs = []*net.IPNet{lo} })
	for i := 0; i < 5; i++ {
		resp, _ := f.do(t, http.MethodPost, "/secrets", `{"content":"x"}`, nil)
		if resp.StatusCode != 201 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
	}
}

func TestSecurityHeadersAndUnknownRoute(t *testing.T) {
	f := newFixture(t, nil)
	for _, path := range []string{"/healthz", "/nope/../etc/passwd", "/s/does-not-exist"} {
		resp, b := f.do(t, http.MethodGet, path, "", nil)
		for h, want := range map[string]string{
			"Cache-Control":          "no-store",
			"Referrer-Policy":        "no-referrer",
			"X-Content-Type-Options": "nosniff",
		} {
			if got := resp.Header.Get(h); got != want {
				t.Fatalf("%s: header %s = %q", path, h, got)
			}
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("%s: missing CSP", path)
		}
		if strings.Contains(string(b), "passwd") || strings.Contains(string(b), "nope") {
			t.Fatalf("%s: response echoes the path: %s", path, b)
		}
	}
	resp, _ := f.do(t, http.MethodGet, "/metrics", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("metrics: %d", resp.StatusCode)
	}
}

func TestHeadDoesNotConsume(t *testing.T) {
	f := newFixture(t, nil)
	c := f.create(t, `{"content":"preview-safe"}`)
	resp, _ := f.do(t, http.MethodHead, "/s/"+c.ID, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("head: %d", resp.StatusCode)
	}
	resp, _ = f.do(t, http.MethodGet, "/s/"+c.ID, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("HEAD consumed the view: %d", resp.StatusCode)
	}
}

func TestValidation(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MaxContentBytes = 32 })
	cases := map[string]int{
		`not json`:                        400,
		`{"content":""}`:                  400,
		`{}`:                              400,
		`{"content":"x","ttl_seconds":0}`: 400,
		`{"content":"x","ttl_seconds":999999999}`: 400,
		`{"content":"x","max_views":0}`:           400,
		`{"content":"x","max_views":101}`:         400,
		`{"content":"` + strings.Repeat("a", 33) + `"}`: 413,
		`{"content":"ok"} trailing`:                     400,
		`{"content":"ok","ttl_seconds":60,"max_views":2}`: 201,
	}
	for body, want := range cases {
		resp, b := f.do(t, http.MethodPost, "/secrets", body, nil)
		if resp.StatusCode != want {
			t.Errorf("%s: want %d got %d (%s)", body, want, resp.StatusCode, b)
		}
	}
}

// TestTimingNotFoundVsWrongPassphrase checks that an unknown id and a wrong
// passphrase on a real id cost about the same when a passphrase is supplied.
func TestTimingNotFoundVsWrongPassphrase(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	f := newFixture(t, func(c *Config) { c.ReadBurst = 10000; c.ReadRate = 10000 })
	c := f.create(t, `{"content":"timed","passphrase":"right"}`)
	bogus := crypto.NewToken()
	hdr := map[string]string{"X-Passphrase": "wrong"}

	measure := func(path string) time.Duration {
		var samples []time.Duration
		for i := 0; i < 12; i++ {
			start := time.Now()
			f.do(t, http.MethodGet, path, "", hdr)
			samples = append(samples, time.Since(start))
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		return samples[len(samples)/2]
	}
	wrong := measure("/s/" + c.ID)
	missing := measure("/s/" + bogus)
	t.Logf("median wrong-passphrase=%v not-found=%v", wrong, missing)
	ratio := float64(wrong) / float64(missing)
	if ratio < 0.5 || ratio > 2 {
		t.Fatalf("timing gap too large: wrong=%v missing=%v", wrong, missing)
	}
}
