package presence

import (
	"strconv"
	"testing"
	"time"

	"deechat/chat-node/internal/model"
)

func TestPresenceLeaseLastSeenAndRevoke(t *testing.T) {
	now := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	store := NewStore(10, 24*time.Hour, func() time.Time { return now })
	if !store.Heartbeat(model.PresenceHeartbeat{OwnerHash: "alice", GrantHash: "grant-a", ExpiresAt: now.Add(90 * time.Second)}) {
		t.Fatal("heartbeat rejected")
	}
	status := store.Query([]string{"grant-a", "unknown"})
	if len(status) != 1 || !status[0].Online || status[0].LastSeen != now {
		t.Fatalf("unexpected online status: %#v", status)
	}
	now = now.Add(2 * time.Minute)
	status = store.Query([]string{"grant-a"})
	if len(status) != 1 || status[0].Online {
		t.Fatalf("expected retained offline last-seen: %#v", status)
	}
	if store.Revoke("alice") != 1 || len(store.Query([]string{"grant-a"})) != 0 {
		t.Fatal("revoke did not remove presence")
	}
}

func TestPresenceExpiresAfterLastSeenTTL(t *testing.T) {
	now := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	store := NewStore(10, 24*time.Hour, func() time.Time { return now })
	store.Heartbeat(model.PresenceHeartbeat{OwnerHash: "alice", GrantHash: "grant-a", ExpiresAt: now.Add(time.Minute)})
	now = now.Add(25 * time.Hour)
	if got := store.Query([]string{"grant-a"}); len(got) != 0 {
		t.Fatalf("expired presence remained: %#v", got)
	}
}

func TestPresenceRevocationPreventsStaleMeshHeartbeat(t *testing.T) {
	now := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	store := NewStore(10, 24*time.Hour, func() time.Time { return now })
	stale := model.PresenceHeartbeat{OwnerHash: "alice", GrantHash: "grant-a", UpdatedAt: now, ExpiresAt: now.Add(90 * time.Second)}
	store.Heartbeat(stale)
	now = now.Add(time.Second)
	store.Revoke("alice")
	store.Import([]model.PresenceHeartbeat{stale})
	if got := store.Query([]string{"grant-a"}); len(got) != 0 {
		t.Fatalf("stale heartbeat restored revoked presence: %#v", got)
	}
}

func TestRevocationTombstonesAreCappedButStillRevoke(t *testing.T) {
	now := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	store := NewStore(2, 24*time.Hour, func() time.Time { return now })

	// A live lease under the third (over-cap) owner; its revocation must still
	// drop the lease even though the tombstone can't be stored.
	store.Heartbeat(model.PresenceHeartbeat{OwnerHash: "owner-3", GrantHash: "grant-3", ExpiresAt: now.Add(time.Minute)})

	for _, owner := range []string{"owner-1", "owner-2", "owner-3"} {
		store.Revoke(owner)
	}

	if got := len(store.Revocations()); got != 2 {
		t.Fatalf("revocation map = %d, want capped at 2", got)
	}
	if got := store.Query([]string{"grant-3"}); len(got) != 0 {
		t.Fatalf("over-cap Revoke did not drop the lease: %#v", got)
	}
}

// The A6 finding, as a test: a burst of junk grant hashes used to fill the table
// and hold it for lastSeenTTL — 24 hours — because a full table refused every
// grant hash it was not already carrying. It now holds the table only for as
// long as its own leases are live.
func TestAFullTableYieldsAnOfflineRecordToANewCaller(t *testing.T) {
	now := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	store := NewStore(4, 24*time.Hour, func() time.Time { return now })
	for index := 0; index < 4; index++ {
		if !store.HeartbeatWithGrant(junk(index, now), Grant{Caller: "tag:flooder"}) {
			t.Fatalf("junk heartbeat %d rejected below capacity", index)
		}
	}
	if store.HeartbeatWithGrant(model.PresenceHeartbeat{OwnerHash: "alice", GrantHash: "grant-a", ExpiresAt: now.Add(time.Minute)}, Grant{Caller: "tag:alice"}) {
		t.Fatal("a live table gave up a slot while every lease in it was online")
	}
	// Five minutes on, every junk lease is offline: still held for the last-seen
	// answer, but with no claim on the slot ahead of a caller that wants one.
	now = now.Add(6 * time.Minute)
	if !store.HeartbeatWithGrant(model.PresenceHeartbeat{OwnerHash: "alice", GrantHash: "grant-a", ExpiresAt: now.Add(time.Minute)}, Grant{Caller: "tag:alice"}) {
		t.Fatal("a new caller was locked out by leases that had gone offline")
	}
	if status := store.Query([]string{"grant-a"}); len(status) != 1 || !status[0].Online {
		t.Fatalf("the new caller is not online: %#v", status)
	}
	if store.Count() != 4 {
		t.Fatalf("the table grew past its cap: %d", store.Count())
	}
}

// The other half of the same finding: a flooder that keeps every one of its
// leases live cannot hold the table either, because a caller past its share has
// a weaker claim on a slot than a caller inside one.
func TestACallerPastItsShareYieldsToOneInsideIt(t *testing.T) {
	now := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	store := NewStore(maxRecordsPerCaller+2, 24*time.Hour, func() time.Time { return now })
	for index := 0; index < maxRecordsPerCaller+2; index++ {
		if !store.HeartbeatWithGrant(junk(index, now), Grant{Caller: "tag:flooder"}) {
			t.Fatalf("junk heartbeat %d rejected below capacity", index)
		}
	}
	if !store.HeartbeatWithGrant(model.PresenceHeartbeat{OwnerHash: "alice", GrantHash: "grant-a", ExpiresAt: now.Add(time.Minute)}, Grant{Caller: "tag:alice"}) {
		t.Fatal("a caller inside its share was refused by one past its own")
	}
	if store.Count() != maxRecordsPerCaller+2 {
		t.Fatalf("the table grew past its cap: %d", store.Count())
	}
	// And the flooder does not win the slot back at somebody else's expense.
	if store.HeartbeatWithGrant(junk(99, now), Grant{Caller: "tag:flooder"}) {
		t.Fatal("a caller past its share took a slot from a live lease")
	}
	if status := store.Query([]string{"grant-a"}); len(status) != 1 || !status[0].Online {
		t.Fatalf("the honest caller lost its lease: %#v", status)
	}
}

// A caller that proved nothing shares one bucket with every other such caller —
// that is the whole of what proof buys — but it is never worse off than it was:
// below capacity nothing is consulted at all.
func TestUnattributedCallersShareOneBucketAndAreNotCappedBelowCapacity(t *testing.T) {
	now := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	store := NewStore(maxRecordsPerCaller*4, 24*time.Hour, func() time.Time { return now })
	for index := 0; index < maxRecordsPerCaller*4; index++ {
		if !store.Heartbeat(junk(index, now)) {
			t.Fatalf("unattributed heartbeat %d refused below capacity", index)
		}
	}
	if store.Count() != maxRecordsPerCaller*4 {
		t.Fatalf("unexpected table size: %d", store.Count())
	}
	if store.Heartbeat(junk(999, now)) {
		t.Fatal("the shared bucket took a slot from a live lease")
	}
	if !store.HeartbeatWithGrant(junk(999, now), Grant{Caller: "tag:alice"}) {
		t.Fatal("a caller with a share of its own was refused")
	}
}

// The counter map is the kind of bookkeeping that leaks silently, so every exit
// a record has is checked: overwritten, revoked, revoked by a replicated
// tombstone, expired, and evicted.
func TestTheCallerCountsNeverOutliveTheirRecords(t *testing.T) {
	now := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	store := NewStore(2, 24*time.Hour, func() time.Time { return now })
	beat := func(owner, grant, caller string) bool {
		return store.HeartbeatWithGrant(model.PresenceHeartbeat{OwnerHash: owner, GrantHash: grant, ExpiresAt: now.Add(time.Minute)}, Grant{Caller: caller})
	}
	counted := func() int {
		store.mu.Lock()
		defer store.mu.Unlock()
		total := 0
		for _, count := range store.callers {
			total += count
		}
		return total
	}

	beat("alice", "grant-a", "tag:alice")
	beat("alice", "grant-a", "tag:alice-again") // the same record under another caller
	beat("bob", "grant-b", "tag:bob")
	if counted() != 2 || store.Count() != 2 {
		t.Fatalf("counts drifted after an overwrite: %d counted, %d records", counted(), store.Count())
	}
	if store.Revoke("alice") != 1 || counted() != 1 {
		t.Fatalf("a revoked record left its count behind: %d", counted())
	}
	beat("carol", "grant-c", "tag:carol")
	store.ImportRevocations([]model.PresenceRevocation{{OwnerHash: "carol", UpdatedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour)}})
	if counted() != 1 {
		t.Fatalf("a replicated revocation left its count behind: %d", counted())
	}
	// An eviction: fill the table, let it go offline, and take a slot.
	beat("dave", "grant-d", "tag:dave")
	now = now.Add(10 * time.Minute)
	beat("erin", "grant-e", "tag:erin")
	if counted() != store.Count() {
		t.Fatalf("an eviction left its count behind: %d counted, %d records", counted(), store.Count())
	}
	// And expiry.
	now = now.Add(25 * time.Hour)
	if store.Count() != 0 || counted() != 0 {
		t.Fatalf("expiry left counts behind: %d counted, %d records", counted(), store.Count())
	}
}

func junk(index int, now time.Time) model.PresenceHeartbeat {
	return model.PresenceHeartbeat{
		OwnerHash: "junk-owner-" + strconv.Itoa(index),
		GrantHash: "junk-grant-" + strconv.Itoa(index),
		ExpiresAt: now.Add(5 * time.Minute),
	}
}
