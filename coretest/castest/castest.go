// Copyright Thesmos 2026
// SPDX-License-Identifier: Apache-2.0

// Package castest holds the conformance suite for
// [go.thesmos.sh/core/cas.Store]: the verification MUST, idempotent
// writes with an exactly-once wrote signal, absence and zero-digest
// classification, and rejection without mutation. Hand-rolled;
// nothing here is generated.
package castest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"go.thesmos.sh/testkit"

	"go.thesmos.sh/core/cas"
	"go.thesmos.sh/core/crypto"
	"go.thesmos.sh/core/crypto/sha256"
	"go.thesmos.sh/core/crypto/sha3"
	"go.thesmos.sh/core/errs"
)

// AssertStore drives a [cas.Store] implementation through the CAS
// laws. newStore must return an empty store bound to the given
// hasher; the suite constructs a fresh one per case, so cases
// cannot observe each other's contents.
//
// The suite verifies with SHA-256 as the bound algorithm and uses
// SHA3-256 — same digest width, different function — to prove the
// store rejects addresses from a foreign algorithm rather than
// storing under a foreign address space.
func AssertStore(t *testing.T, newStore func(h crypto.Hasher) cas.Store) {
	t.Helper()

	h := sha256.New()
	payload := []byte("cas conformance payload")

	t.Run("put-get round-trips an independent slice", func(t *testing.T) {
		t.Parallel()

		s := newStore(h)
		d := h.Hash(payload)

		wrote, err := s.Put(t.Context(), d, payload)
		testkit.NoError(t, err, "a verified Put must succeed")
		testkit.True(t, wrote, "the first Put of an address must report wrote")

		got, err := s.Get(t.Context(), d)
		testkit.NoError(t, err, "Get of a present address must succeed")
		testkit.Equal(t, got, payload, "the round trip must be exact")

		// The returned slice is the caller's: mutating it must not
		// affect what a later reader observes.
		got[0] ^= 0xFF

		again, err := s.Get(t.Context(), d)
		testkit.NoError(t, err, "Get must succeed after a caller mutation")
		testkit.Equal(t, again, payload,
			"a caller mutating its slice must not reach the store")
	})

	t.Run("re-put of identical bytes is an idempotent no-op", func(t *testing.T) {
		t.Parallel()

		s := newStore(h)
		d := h.Hash(payload)

		_, err := s.Put(t.Context(), d, payload)
		testkit.NoError(t, err, "the first Put must succeed")

		wrote, err := s.Put(t.Context(), d, payload)
		testkit.NoError(t, err, "a duplicate Put must not error")
		testkit.False(t, wrote, "a duplicate Put must report wrote=false")
	})

	t.Run("a wrong digest is Integrity and stores nothing", func(t *testing.T) {
		t.Parallel()

		s := newStore(h)
		d := h.Hash([]byte("other bytes entirely"))

		wrote, err := s.Put(t.Context(), d, payload)
		testkit.False(t, wrote, "a failed Put must not report wrote")
		testkit.Equal(t, errs.Classify(err), errs.Integrity,
			"data that does not hash to its address must classify as Integrity")

		ok, err := s.Has(t.Context(), d)
		testkit.NoError(t, err, "Has must succeed after a rejected Put")
		testkit.False(t, ok, "a rejected Put must store nothing")
	})

	t.Run("a foreign algorithm's digest is Integrity", func(t *testing.T) {
		t.Parallel()

		// SHA3-256 of the same bytes: same width, different
		// function. Size cannot discriminate algorithm; only
		// recomputation can.
		s := newStore(h)
		foreign := sha3.New256().Hash(payload)

		wrote, err := s.Put(t.Context(), foreign, payload)
		testkit.False(t, wrote, "a foreign address must not be written")
		testkit.Equal(t, errs.Classify(err), errs.Integrity,
			"an address from another algorithm must fail verification")

		ok, err := s.Has(t.Context(), foreign)
		testkit.NoError(t, err, "Has must succeed after the rejection")
		testkit.False(t, ok, "nothing may be stored under a foreign address")
	})

	t.Run("Has agrees with Get on presence and absence", func(t *testing.T) {
		t.Parallel()

		s := newStore(h)
		present := h.Hash(payload)
		absent := h.Hash([]byte("never stored"))

		_, err := s.Put(t.Context(), present, payload)
		testkit.NoError(t, err, "Put must succeed")

		ok, err := s.Has(t.Context(), present)
		testkit.NoError(t, err, "Has of a present address must succeed")
		testkit.True(t, ok, "Has must report a stored address")

		ok, err = s.Has(t.Context(), absent)
		testkit.NoError(t, err, "Has of an absent address must succeed")
		testkit.False(t, ok, "Has must not report an absent address")

		_, err = s.Get(t.Context(), absent)
		testkit.Equal(t, errs.Classify(err), errs.NotFound,
			"an absent address on Get must classify as NotFound")
	})

	t.Run("the zero digest is Invalid on every method", func(t *testing.T) {
		t.Parallel()

		s := newStore(h)

		var zero crypto.Digest

		_, perr := s.Put(t.Context(), zero, payload)
		testkit.Equal(t, errs.Classify(perr), errs.Invalid,
			"Put of the zero digest must classify as Invalid")

		_, gerr := s.Get(t.Context(), zero)
		testkit.Equal(t, errs.Classify(gerr), errs.Invalid,
			"Get of the zero digest must classify as Invalid")

		_, herr := s.Has(t.Context(), zero)
		testkit.Equal(t, errs.Classify(herr), errs.Invalid,
			"Has of the zero digest must classify as Invalid")
	})

	t.Run("empty data is a legal value", func(t *testing.T) {
		t.Parallel()

		s := newStore(h)
		d := h.Hash(nil)

		wrote, err := s.Put(t.Context(), d, nil)
		testkit.NoError(t, err, "the digest of zero bytes is a valid address")
		testkit.True(t, wrote, "the first Put of the empty value must write")

		got, err := s.Get(t.Context(), d)
		testkit.NoError(t, err, "Get of the empty value must succeed")
		testkit.Len(t, got, 0, "the empty value must round-trip empty")
	})

	t.Run("a done context surfaces on every method", func(t *testing.T) {
		t.Parallel()

		s := newStore(h)
		d := h.Hash(payload)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := s.Put(ctx, d, payload)
		testkit.ErrorIs(t, err, context.Canceled, "a cancelled Put must report the context")

		_, err = s.Get(ctx, d)
		testkit.ErrorIs(t, err, context.Canceled, "a cancelled Get must report the context")

		_, err = s.Has(ctx, d)
		testkit.ErrorIs(t, err, context.Canceled, "a cancelled Has must report the context")
	})

	t.Run("concurrent puts of one address write exactly once", func(t *testing.T) {
		t.Parallel()

		s := newStore(h)
		d := h.Hash(payload)

		var (
			wrote atomic.Int64
			wg    sync.WaitGroup
		)
		for range 16 {
			wg.Go(func() {
				ok, err := s.Put(t.Context(), d, payload)
				testkit.NoError(t, err, "concurrent identical Puts must all succeed")
				if ok {
					wrote.Add(1)
				}
			})
		}
		wg.Wait()

		testkit.Equal(t, wrote.Load(), int64(1),
			"exactly one concurrent Put may report wrote — it is an accounting signal")

		got, err := s.Get(t.Context(), d)
		testkit.NoError(t, err, "the value must be readable after the race")
		testkit.Equal(t, got, payload, "the raced value must be intact")
	})
}
