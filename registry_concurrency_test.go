// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

// concurrentURI builds a distinct event-type URI for goroutine index i. The
// registry is process-wide and panics on a duplicate registration, so every
// concurrent RegisterEventType must claim a URI no other goroutine — or earlier
// test — uses. Indexing by i guarantees that within this test, and the
// test-specific path segment keeps it disjoint from the URIs the other registry
// tests register.
func concurrentURI(i int) string {
	return fmt.Sprintf("https://schemas.example.com/secevent/test/event-type/concurrent/%d", i)
}

// TestRegistryConcurrentAccess exercises the package-level registry's RWMutex
// under contention: many goroutines call RegisterEventType (each with a distinct
// URI, so none hits the legitimate duplicate-registration panic) while other
// goroutines concurrently call LookupEventType and Events.Typed against the
// URIs being written. A sync.WaitGroup start barrier releases every goroutine at
// once to maximize the overlap of readers and the lone-writer-at-a-time path.
//
// The test asserts two things. Under go test -race (CI runs -race -shuffle=on)
// it proves the registry's read/write locking admits no data race between
// concurrent registrations and lookups — the property that justifies the
// sync.RWMutex in the registry's design rather than an unsynchronized map. Then,
// after every writer has returned, it confirms each registered URI resolves to a
// working decoder that round-trips its payload and reports the matching
// EventTypeURI, so the concurrent writes all landed correctly and none clobbered
// another.
func TestRegistryConcurrentAccess(t *testing.T) {
	const writers = 64

	var (
		start   sync.WaitGroup // barrier: released once to fire all goroutines together
		writeWG sync.WaitGroup // joins the registering goroutines
		readWG  sync.WaitGroup // joins the concurrent readers
	)
	start.Add(1)

	// Writers: each registers its own distinct URI. The reads inside (LookupEventType,
	// Events.Typed) may observe the entry either before or after this goroutine's
	// write lands; both outcomes are valid and neither may race.
	for i := range writers {
		writeWG.Go(func() {
			uri := concurrentURI(i)
			start.Wait()
			RegisterEventType(uri, decodeFake(uri))
		})
	}

	// Readers: hammer LookupEventType and Events.Typed against the same URIs while
	// the writers register them. A reader seeing ok == false (the write has not
	// landed yet) is expected; the point is to drive the RLock path concurrently
	// with the writers' Lock path, not to assert a particular interleaving. t.Errorf
	// is safe to call from these goroutines; t.Fatal-family calls are not, so the
	// readers only ever Errorf.
	for i := range writers {
		readWG.Go(func() {
			uri := concurrentURI(i)
			ev := Events{uri: json.RawMessage(`{"subject":"bob"}`)}
			start.Wait()
			for range 100 {
				if decode, ok := LookupEventType(uri); ok && decode == nil {
					t.Errorf("LookupEventType(%q) ok = true with nil decoder", uri)
				}
				if _, _, err := ev.Typed(uri); err != nil {
					t.Errorf("Typed(%q) err = %v during concurrent registration", uri, err)
				}
			}
		})
	}

	start.Done() // release the barrier
	writeWG.Wait()
	readWG.Wait()

	// Every writer has returned, so every URI must now resolve to its own working
	// decoder. This confirms the concurrent writes all persisted and that no
	// registration overwrote another's entry.
	for i := range writers {
		uri := concurrentURI(i)
		decode, ok := LookupEventType(uri)
		if !ok {
			t.Errorf("LookupEventType(%q) ok = false after concurrent registration, want true", uri)
			continue
		}
		if decode == nil {
			t.Errorf("LookupEventType(%q) returned nil decoder with ok = true", uri)
			continue
		}
		event, err := decode(json.RawMessage(`{"subject":"carol"}`))
		if err != nil {
			t.Errorf("decode for %q: %v", uri, err)
			continue
		}
		if got := event.EventTypeURI(); got != uri {
			t.Errorf("decoder for %q returned EventTypeURI() = %q, want the registered URI", uri, got)
		}
	}
}
