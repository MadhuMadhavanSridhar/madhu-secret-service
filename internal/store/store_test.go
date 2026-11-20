package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	m := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb, "testkek0", 3)
}

func put(t *testing.T, s *Store, lookup string, maxViews int, pass bool) {
	t.Helper()
	rec := Record{
		Ciphertext:   []byte("ciphertext-bytes"),
		MaxViews:     maxViews,
		ExpiresAt:    time.Now().Add(time.Hour),
		DeletionHash: "deadbeef",
	}
	if pass {
		rec.PassSalt = []byte("salt")
		rec.PassVerifier = []byte("verifier")
	}
	if err := s.Put(context.Background(), lookup, rec); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeExactlyOnceUnderRace(t *testing.T) {
	for _, maxViews := range []int{1, 5} {
		s := newStore(t)
		put(t, s, "race", maxViews, false)

		const n = 50
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok, notFound := 0, 0
		start := make(chan struct{})
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				res, err := s.Consume(context.Background(), "race", time.Now(), PassNone)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				switch res.Outcome {
				case OutcomeOK:
					ok++
				case OutcomeNotFound:
					notFound++
				default:
					t.Errorf("unexpected outcome %d", res.Outcome)
				}
			}()
		}
		close(start)
		wg.Wait()
		if ok != maxViews || notFound != n-maxViews {
			t.Fatalf("max_views=%d: got %d ok and %d not found", maxViews, ok, notFound)
		}
		// Nothing left behind.
		res, err := s.Consume(context.Background(), "race", time.Now(), PassNone)
		if err != nil || res.Outcome != OutcomeNotFound {
			t.Fatalf("expected not found after exhaustion, got %v %v", res.Outcome, err)
		}
	}
}

func TestConsumeExpiryIsCheckedInScript(t *testing.T) {
	s := newStore(t)
	rec := Record{Ciphertext: []byte("x"), MaxViews: 1, ExpiresAt: time.Now().Add(10 * time.Second), DeletionHash: "h"}
	if err := s.Put(context.Background(), "exp", rec); err != nil {
		t.Fatal(err)
	}
	res, err := s.Consume(context.Background(), "exp", time.Now().Add(11*time.Second), PassNone)
	if err != nil || res.Outcome != OutcomeNotFound {
		t.Fatalf("expected not found past expiry, got %v %v", res.Outcome, err)
	}
}

func TestPassphraseFlowAndBurn(t *testing.T) {
	s := newStore(t)
	put(t, s, "p", 1, true)
	ctx := context.Background()

	res, _ := s.Consume(ctx, "p", time.Now(), PassNone)
	if res.Outcome != OutcomePassRequired {
		t.Fatalf("expected passphrase required, got %v", res.Outcome)
	}
	// A wrong passphrase must not consume a view.
	for i := 0; i < 2; i++ {
		res, _ = s.Consume(ctx, "p", time.Now(), PassBad)
		if res.Outcome != OutcomePassWrong || res.Burned {
			t.Fatalf("attempt %d: expected wrong (not burned), got %+v", i, res)
		}
	}
	res, _ = s.Consume(ctx, "p", time.Now(), PassOK)
	if res.Outcome != OutcomeOK || string(res.Ciphertext) != "ciphertext-bytes" || !res.Exhausted {
		t.Fatalf("expected success, got %+v", res)
	}

	// Third failure burns the record.
	put(t, s, "q", 1, true)
	for i := 0; i < 3; i++ {
		res, _ = s.Consume(ctx, "q", time.Now(), PassBad)
	}
	if res.Outcome != OutcomePassWrong || !res.Burned {
		t.Fatalf("expected burned, got %+v", res)
	}
	res, _ = s.Consume(ctx, "q", time.Now(), PassOK)
	if res.Outcome != OutcomeNotFound {
		t.Fatalf("expected gone after burn, got %+v", res)
	}
}

func TestDeleteRequiresMatchingHash(t *testing.T) {
	s := newStore(t)
	put(t, s, "d", 1, false)
	ctx := context.Background()
	if ok, _ := s.Delete(ctx, "d", "wrong"); ok {
		t.Fatal("wrong hash deleted the record")
	}
	if ok, _ := s.Delete(ctx, "d", "deadbeef"); !ok {
		t.Fatal("right hash did not delete")
	}
	if ok, _ := s.Delete(ctx, "d", "deadbeef"); ok {
		t.Fatal("second delete reported success")
	}
	res, _ := s.Consume(ctx, "d", time.Now(), PassNone)
	if res.Outcome != OutcomeNotFound {
		t.Fatal("record readable after delete")
	}
}
