package prekey

import (
	"fmt"
	"testing"
	"time"

	"deechat/chat-node/internal/model"
)

func publish(t *testing.T, store *Store, recipient string, ids ...string) {
	t.Helper()
	publishDevice(t, store, recipient, "", ids...)
}

func publishDevice(t *testing.T, store *Store, recipient, device string, ids ...string) {
	t.Helper()
	entries := make([]model.PrekeyEntry, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, model.PrekeyEntry{OpkID: id, PublicKey: "pub-" + id, Signature: "sig-" + id})
	}
	if _, ok := store.Publish(recipient, model.PrekeyPublish{DeviceKey: device, Entries: entries}); !ok {
		t.Fatalf("publish for %q/%q was refused at the bucket ceiling", recipient, device)
	}
}

func TestClaimReturnsDistinctEntriesAndDrains(t *testing.T) {
	store := NewStore(0, 0, func() time.Time { return time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC) })
	publish(t, store, "bob", "opk-1", "opk-2")
	if store.Status("bob", "") != 2 {
		t.Fatalf("status = %d, want 2", store.Status("bob", ""))
	}

	first, ok := store.Claim("bob", "")
	if !ok {
		t.Fatal("first claim failed")
	}
	second, ok := store.Claim("bob", "")
	if !ok {
		t.Fatal("second claim failed")
	}
	if first.OpkID == second.OpkID {
		t.Fatalf("claim-once violated: both claims returned %q", first.OpkID)
	}

	if _, ok := store.Claim("bob", ""); ok {
		t.Fatal("drained pool returned a prekey")
	}
	if store.Status("bob", "") != 0 {
		t.Fatalf("drained status = %d, want 0", store.Status("bob", ""))
	}
}

func TestClaimUnknownRecipientReturnsEmpty(t *testing.T) {
	store := NewStore(0, 0, nil)
	if _, ok := store.Claim("nobody", ""); ok {
		t.Fatal("claim for unknown recipient returned a prekey")
	}
}

func TestPublishEnforcesCapAndDeduplicates(t *testing.T) {
	store := NewStore(3, 0, func() time.Time { return time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC) })
	publish(t, store, "bob", "opk-1", "opk-2", "opk-3", "opk-4")
	if got := store.Status("bob", ""); got != 3 {
		t.Fatalf("status = %d, want cap of 3", got)
	}
	// Replenish with an overlapping id and a fresh id; cap is already full so
	// nothing new is admitted, and the duplicate is skipped regardless.
	added, ok := store.Publish("bob", model.PrekeyPublish{Entries: []model.PrekeyEntry{
		{OpkID: "opk-1", PublicKey: "pub", Signature: "sig"},
	}})
	if !ok {
		t.Fatal("replenish of an existing bucket was refused")
	}
	if added != 0 {
		t.Fatalf("duplicate publish added = %d, want 0", added)
	}
}

// TestDeviceScopedPoolsAreIndependent verifies that two devices of one recipient
// hold independent pools: a claim for device A never yields device B's prekey,
// and the per-bucket cap applies per device.
func TestDeviceScopedPoolsAreIndependent(t *testing.T) {
	store := NewStore(0, 0, func() time.Time { return time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC) })
	publishDevice(t, store, "bob", "devA", "a-1", "a-2")
	publishDevice(t, store, "bob", "devB", "b-1")

	if got := store.Status("bob", "devA"); got != 2 {
		t.Fatalf("devA status = %d, want 2", got)
	}
	if got := store.Status("bob", "devB"); got != 1 {
		t.Fatalf("devB status = %d, want 1", got)
	}
	// Legacy recipient-only bucket is empty: neither device published into it.
	if got := store.Status("bob", ""); got != 0 {
		t.Fatalf("legacy status = %d, want 0", got)
	}

	// Drain devB; devA's pool is untouched, and devB never returns devA's keys.
	claimed, ok := store.Claim("bob", "devB")
	if !ok || claimed.OpkID != "b-1" {
		t.Fatalf("devB claim = %q, ok=%v, want b-1", claimed.OpkID, ok)
	}
	if _, ok := store.Claim("bob", "devB"); ok {
		t.Fatal("drained devB pool returned a prekey")
	}
	if got := store.Status("bob", "devA"); got != 2 {
		t.Fatalf("devA status after devB drain = %d, want 2", got)
	}
}

func TestPerBucketCapIsPerDevice(t *testing.T) {
	store := NewStore(2, 0, func() time.Time { return time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC) })
	publishDevice(t, store, "bob", "devA", "a-1", "a-2", "a-3")
	publishDevice(t, store, "bob", "devB", "b-1", "b-2", "b-3")
	if got := store.Status("bob", "devA"); got != 2 {
		t.Fatalf("devA status = %d, want cap of 2", got)
	}
	if got := store.Status("bob", "devB"); got != 2 {
		t.Fatalf("devB status = %d, want cap of 2", got)
	}
}

func TestPrunesExpiredEntries(t *testing.T) {
	now := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	store := NewStore(0, time.Hour, func() time.Time { return now })
	publish(t, store, "bob", "opk-1")
	now = now.Add(2 * time.Hour)
	if got := store.Status("bob", ""); got != 0 {
		t.Fatalf("expired prekey remained: status = %d", got)
	}
	if _, ok := store.Claim("bob", ""); ok {
		t.Fatal("expired prekey was claimable")
	}
}

func publishLastResort(t *testing.T, store *Store, recipient, device, id string) {
	t.Helper()
	if _, ok := store.Publish(recipient, model.PrekeyPublish{
		DeviceKey:  device,
		LastResort: &model.PrekeyEntry{OpkID: id, PublicKey: "pub-" + id, Signature: "sig-" + id},
	}); !ok {
		t.Fatalf("last-resort publish for %q/%q was refused at the bucket ceiling", recipient, device)
	}
}

// TestClaimBurstServesLastResortWithoutDrainingOneTime verifies the coupling:
// once the per-bucket token bucket is exhausted, further claims are throttled
// onto the reusable last-resort prekey, leaving the genuine one-time entries
// intact for the legitimate trickle.
func TestClaimBurstServesLastResortWithoutDrainingOneTime(t *testing.T) {
	now := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	// Burst of 2, slow refill so the bucket can't recover mid-test.
	store := NewStoreWithLimits(Limits{ClaimBurst: 2, ClaimRefill: time.Hour}, func() time.Time { return now })
	publish(t, store, "bob", "opk-1", "opk-2", "opk-3", "opk-4")
	publishLastResort(t, store, "bob", "", "lrpk-1")

	// First two claims spend the burst and pop distinct one-time entries.
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		got, ok := store.Claim("bob", "")
		if !ok || got.LastResort {
			t.Fatalf("claim %d: ok=%v lastResort=%v, want a one-time entry", i, ok, got.LastResort)
		}
		if seen[got.OpkID] {
			t.Fatalf("claim-once violated: %q twice", got.OpkID)
		}
		seen[got.OpkID] = true
	}

	// The next claims are throttled onto the reusable last-resort prekey.
	for i := 0; i < 3; i++ {
		got, ok := store.Claim("bob", "")
		if !ok || !got.LastResort || got.OpkID != "lrpk-1" {
			t.Fatalf("throttled claim %d = %q lastResort=%v ok=%v, want lrpk-1", i, got.OpkID, got.LastResort, ok)
		}
	}

	// The one-time pool kept its remaining (4 - 2) entries — they were not burned.
	if got := store.Status("bob", ""); got != 2 {
		t.Fatalf("one-time status = %d, want 2 preserved", got)
	}
}

// TestClaimDrainedQueueServesLastResort: with the token available but the
// one-time queue empty, the last-resort prekey is served (never the v2 path).
func TestClaimDrainedQueueServesLastResort(t *testing.T) {
	now := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	store := NewStoreWithLimits(Limits{ClaimBurst: 100, ClaimRefill: time.Second}, func() time.Time { return now })
	publish(t, store, "bob", "opk-1")
	publishLastResort(t, store, "bob", "", "lrpk-1")

	first, ok := store.Claim("bob", "")
	if !ok || first.LastResort {
		t.Fatalf("first claim ok=%v lastResort=%v, want the one-time entry", ok, first.LastResort)
	}
	// Queue now empty, tokens still plentiful → last-resort.
	got, ok := store.Claim("bob", "")
	if !ok || !got.LastResort || got.OpkID != "lrpk-1" {
		t.Fatalf("drained claim = %q lastResort=%v ok=%v, want lrpk-1", got.OpkID, got.LastResort, ok)
	}
}

// TestClaimDrainedWithoutLastResortFallsBack: a legacy recipient that never
// published an LRPK still drains to (zero,false) so the sender uses v2.
func TestClaimDrainedWithoutLastResortFallsBack(t *testing.T) {
	now := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	store := NewStoreWithLimits(Limits{ClaimBurst: 100, ClaimRefill: time.Second}, func() time.Time { return now })
	publish(t, store, "bob", "opk-1")
	if _, ok := store.Claim("bob", ""); !ok {
		t.Fatal("first claim failed")
	}
	if got, ok := store.Claim("bob", ""); ok {
		t.Fatalf("drained pool without LRPK returned %q (ok), want v2 fallback", got.OpkID)
	}
}

// TestPublishReplacesLastResort: a later publish replaces the prior LRPK.
func TestPublishReplacesLastResort(t *testing.T) {
	now := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	store := NewStoreWithLimits(Limits{}, func() time.Time { return now })
	publishLastResort(t, store, "bob", "", "lrpk-1")
	publishLastResort(t, store, "bob", "", "lrpk-2")
	if got := store.LastResortCount(); got != 1 {
		t.Fatalf("last-resort count = %d, want 1 (replaced)", got)
	}
	got, ok := store.Claim("bob", "")
	if !ok || got.OpkID != "lrpk-2" {
		t.Fatalf("claim after replace = %q ok=%v, want lrpk-2", got.OpkID, ok)
	}
}

func TestCountAcrossRecipients(t *testing.T) {
	store := NewStore(0, 0, nil)
	for i := 0; i < 5; i++ {
		publish(t, store, fmt.Sprintf("r-%d", i), fmt.Sprintf("opk-%d", i))
	}
	if store.Count() != 5 {
		t.Fatalf("count = %d, want 5", store.Count())
	}
}

// TestBucketCeilingRefusesNewPoolsAndKeepsExistingOnes is the cap that did not
// exist: every other store in the node bounds what one identity can occupy, and
// this one bounded the keys per pool while nothing bounded the pools. The two
// halves that matter are asserted together, because a ceiling that refused
// everybody at capacity would trade an unbounded map for a dead relay.
func TestBucketCeilingRefusesNewPoolsAndKeepsExistingOnes(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	store := NewStoreWithLimits(Limits{MaxBuckets: 2}, func() time.Time { return now })

	for _, recipient := range []string{"r-1", "r-2"} {
		if _, ok := store.Publish(recipient, model.PrekeyPublish{
			Entries: []model.PrekeyEntry{{OpkID: "opk-" + recipient, PublicKey: "pub", Signature: "sig"}},
		}); !ok {
			t.Fatalf("publish for %s was refused below the ceiling", recipient)
		}
	}
	if got := store.BucketCount(); got != 2 {
		t.Fatalf("bucket count = %d, want 2", got)
	}

	added, ok := store.Publish("r-3", model.PrekeyPublish{
		Entries: []model.PrekeyEntry{{OpkID: "opk-3", PublicKey: "pub", Signature: "sig"}},
	})
	if ok || added != 0 {
		t.Fatalf("publish past the ceiling: added=%d ok=%v, want 0/false", added, ok)
	}
	if got := store.BucketCount(); got != 2 {
		t.Fatalf("refused publish still grew the store: bucket count = %d, want 2", got)
	}
	if _, ok := store.Claim("r-3", ""); ok {
		t.Fatal("a refused publish left a claimable prekey behind")
	}

	// A recipient already carried is never refused, so a box at capacity keeps
	// replenishing the pools it has rather than letting them drain to v2.
	if _, ok := store.Publish("r-1", model.PrekeyPublish{
		Entries: []model.PrekeyEntry{{OpkID: "opk-1b", PublicKey: "pub", Signature: "sig"}},
	}); !ok {
		t.Fatal("replenish of an existing pool was refused at the ceiling")
	}
	if got := store.Status("r-1", ""); got != 2 {
		t.Fatalf("existing pool status = %d, want 2 after replenish", got)
	}
}

// TestBucketCeilingCountsLastResortOnlyPools: a device that has published only
// a last-resort prekey still occupies a pool, and it is the last-resort map
// that holds it — count one bucket, not two, and not zero.
func TestBucketCeilingCountsLastResortOnlyPools(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	store := NewStoreWithLimits(Limits{MaxBuckets: 1}, func() time.Time { return now })
	publishLastResort(t, store, "bob", "", "lrpk-1")

	if got := store.BucketCount(); got != 1 {
		t.Fatalf("bucket count = %d, want 1 for a last-resort-only pool", got)
	}
	if _, ok := store.Publish("mallory", model.PrekeyPublish{
		LastResort: &model.PrekeyEntry{OpkID: "lrpk-m", PublicKey: "pub", Signature: "sig"},
	}); ok {
		t.Fatal("a last-resort publish opened a pool past the ceiling")
	}
	if _, ok := store.Claim("mallory", ""); ok {
		t.Fatal("the refused last-resort prekey was served")
	}
	// bob holds entries in both maps and must still count once.
	publish(t, store, "bob", "opk-1")
	if got := store.BucketCount(); got != 1 {
		t.Fatalf("bucket count = %d, want 1 (one device in both maps)", got)
	}
}

// TestExpiredBucketFreesItsSlot: buckets are TTL-pruned, and the ceiling has to
// see that. Otherwise a relay refuses new recipients forever once it has ever
// been full, which is the failure the eviction-free design would deserve.
func TestExpiredBucketFreesItsSlot(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := NewStoreWithLimits(Limits{MaxBuckets: 1, PublishedTTL: time.Hour}, clock)
	publish(t, store, "bob", "opk-1")

	now = now.Add(2 * time.Hour)
	if _, ok := store.Publish("carol", model.PrekeyPublish{
		Entries: []model.PrekeyEntry{{OpkID: "opk-c", PublicKey: "pub", Signature: "sig"}},
	}); !ok {
		t.Fatal("an expired pool held its slot against a new recipient")
	}
	if got := store.BucketCount(); got != 1 {
		t.Fatalf("bucket count = %d, want 1 (bob expired, carol took the slot)", got)
	}
}
