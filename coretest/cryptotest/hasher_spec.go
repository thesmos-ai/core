// Copyright Thesmos 2026
// SPDX-License-Identifier: Apache-2.0

package cryptotest

import (
	"bytes"
	"testing"

	"go.thesmos.sh/testkit"

	"go.thesmos.sh/core/crypto"
)

// HasherContractAssertions returns the generic assertions every
// [crypto.Hasher] implementation must satisfy: determinism,
// stream / Hash equivalence, Sum-non-resetting, Reset semantics.
// Compose with [HasherIDAssertion], [HasherAlgorithmAssertion],
// and [HasherCrossStdlibAssertion] at the consumer call site to
// add impl-specific constants and byte-exact stdlib equivalence.
//
//	cryptotest.AssertHasherContract(t, factory,
//	    append(cryptotest.HasherContractAssertions(),
//	        cryptotest.HasherIDAssertion(wantID),
//	        cryptotest.HasherAlgorithmAssertion(crypto.AlgSHA256),
//	        cryptotest.HasherCrossStdlibAssertion(stdlibSum),
//	    )...,
//	)
func HasherContractAssertions() []HasherOption {
	return []HasherOption{
		// --- Hash ---

		HasherCustom("Hash is deterministic", func(t *testing.T, h crypto.Hasher) {
			input := []byte("the quick brown fox jumps over the lazy dog")
			testkit.True(t, h.Hash(input).Equal(h.Hash(input)),
				"Hash(x) must equal Hash(x) — Hash must be deterministic")
		}),

		HasherCustom("Hash of nil equals Hash of empty slice", func(t *testing.T, h crypto.Hasher) {
			testkit.True(t, h.Hash(nil).Equal(h.Hash([]byte{})),
				"Hash(nil) must equal Hash([]byte{})")
		}),

		HasherCustom("distinct inputs produce distinct digests", func(t *testing.T, h crypto.Hasher) {
			testkit.False(t, h.Hash([]byte("alpha")).Equal(h.Hash([]byte("beta"))),
				"distinct inputs must not collide to the same digest")
		}),

		// --- Combine ---

		HasherCustom("Combine is deterministic", func(t *testing.T, h crypto.Hasher) {
			a := h.Hash([]byte("a"))
			b := h.Hash([]byte("b"))
			testkit.True(t, h.Combine(a, b).Equal(h.Combine(a, b)),
				"Combine(a,b) must equal Combine(a,b) — Combine must be deterministic")
		}),

		HasherCustom("Combine is asymmetric", func(t *testing.T, h crypto.Hasher) {
			a := h.Hash([]byte("a"))
			b := h.Hash([]byte("b"))
			testkit.False(t, h.Combine(a, b).Equal(h.Combine(b, a)),
				"Combine(a,b) must not equal Combine(b,a) — order must matter")
		}),

		// --- Tagged (domain-separated) ---
		//
		// The roles below are example bytes. Core ships none, and a
		// hasher passing these makes no claim about which roles any
		// protocol assigns — what is asserted is the byte layout and
		// the arity split, both of which every implementation owes.

		HasherCustom("HashTagged is the role byte followed by the data", func(t *testing.T, h crypto.Hasher) {
			data := []byte(`{"act":"infer","id":1}`)
			framed := append([]byte{0x01}, data...)
			testkit.True(t, h.HashTagged(0x01, data).Equal(h.Hash(framed)),
				"HashTagged(r, data) must equal Hash(r || data) — one role byte, no framing")
		}),

		HasherCustom("CombineTagged is the role byte followed by both operands", func(t *testing.T, h crypto.Hasher) {
			left := h.Hash([]byte("left"))
			right := h.Hash([]byte("right"))
			framed := append([]byte{0x84}, left.Bytes()...)
			framed = append(framed, right.Bytes()...)
			testkit.True(t, h.CombineTagged(0x84, left, right).Equal(h.Hash(framed)),
				"CombineTagged(r, l, x) must equal Hash(r || l || x) — no length prefixes")
		}),

		HasherCustom("HashTagged accepts empty data", func(t *testing.T, h crypto.Hasher) {
			testkit.True(t, h.HashTagged(0x01, nil).Equal(h.Hash([]byte{0x01})),
				"HashTagged(r, nil) must equal Hash of the role byte alone")
		}),

		HasherCustom("tagged operations are deterministic", func(t *testing.T, h crypto.Hasher) {
			left := h.Hash([]byte("left"))
			right := h.Hash([]byte("right"))
			testkit.True(t, h.HashTagged(0x01, []byte("x")).Equal(h.HashTagged(0x01, []byte("x"))),
				"HashTagged must be deterministic")
			testkit.True(t, h.CombineTagged(0x84, left, right).Equal(h.CombineTagged(0x84, left, right)),
				"CombineTagged must be deterministic")
			testkit.False(t, h.CombineTagged(0x84, left, right).Equal(h.CombineTagged(0x84, right, left)),
				"CombineTagged must be asymmetric — operand order must matter")
		}),

		HasherCustom("a crafted leaf cannot collide with an interior node", func(t *testing.T, h crypto.Hasher) {
			// The second preimage the role byte exists to close: a
			// caller-chosen payload equal to two concatenated sibling
			// digests, offered as a leaf.
			left := h.Hash([]byte("left"))
			right := h.Hash([]byte("right"))
			payload := append(append([]byte{}, left.Bytes()...), right.Bytes()...)
			testkit.False(t, h.HashTagged(0x01, payload).Equal(h.CombineTagged(0x84, left, right)),
				"a payload of two concatenated digests must not hash to their interior node")
		}),

		HasherCustom("distinct binary roles over one pair give distinct digests", func(t *testing.T, h crypto.Hasher) {
			// A chain link, a batch node and an accumulator node are all
			// interior and must not collide with each other — the
			// multiplicity a fixed two-value scheme cannot express.
			left := h.Hash([]byte("left"))
			right := h.Hash([]byte("right"))
			link := h.CombineTagged(0x83, left, right)
			node := h.CombineTagged(0x84, left, right)
			mmr := h.CombineTagged(0x85, left, right)
			testkit.False(t, link.Equal(node), "roles 0x83 and 0x84 must not collide")
			testkit.False(t, node.Equal(mmr), "roles 0x84 and 0x85 must not collide")
			testkit.False(t, link.Equal(mmr), "roles 0x83 and 0x85 must not collide")
		}),

		HasherCustom("the arity halves refuse each other at 0x80", func(t *testing.T, h crypto.Hasher) {
			// The refusal IS the mechanism: without it one role could
			// serve both a leaf and a node, and the collision above
			// becomes constructible again. Only a refusal test proves a
			// guard exists.
			d := h.Hash(nil)

			// The boundary itself — these must not panic, and a panic
			// fails the assertion directly.
			_ = h.HashTagged(0x7F, nil)
			_ = h.CombineTagged(0x80, d, d)

			testkit.Panics(t, func() { _ = h.HashTagged(0x80, nil) },
				"HashTagged must refuse the lowest binary role")
			testkit.Panics(t, func() { _ = h.HashTagged(0xFF, []byte("x")) },
				"HashTagged must refuse the highest binary role")
			testkit.Panics(t, func() { _ = h.CombineTagged(0x7F, d, d) },
				"CombineTagged must refuse the highest unary role")
			testkit.Panics(t, func() { _ = h.CombineTagged(0x00, d, d) },
				"CombineTagged must refuse the lowest unary role")
		}),

		HasherCustom("CombineTagged refuses the zero Digest", func(t *testing.T, h crypto.Hasher) {
			// There is no genesis sentinel in the tagged vocabulary: a
			// chain's first link is a unary role over one operand.
			var zero crypto.Digest
			d := h.Hash(nil)

			testkit.True(t, zero.IsZero(), "the zero Digest must report IsZero")
			testkit.Panics(t, func() { _ = h.CombineTagged(0x84, zero, d) },
				"CombineTagged(r, zero, x) must panic")
			testkit.Panics(t, func() { _ = h.CombineTagged(0x84, d, zero) },
				"CombineTagged(r, x, zero) must panic")
		}),

		HasherCustom("CombineTagged refuses a wrong-width operand", func(t *testing.T, h crypto.Hasher) {
			d := h.Hash(nil)
			wrong := otherWidthDigest(d.Size())

			testkit.False(t, wrong.IsZero(),
				"the wrong-width probe must not be the zero Digest — that is a distinct refusal")
			testkit.Panics(t, func() { _ = h.CombineTagged(0x84, wrong, d) },
				"CombineTagged(r, wrong-left, correct) must panic")
			testkit.Panics(t, func() { _ = h.CombineTagged(0x84, d, wrong) },
				"CombineTagged(r, correct, wrong-right) must panic")
		}),

		// --- Stream ---

		HasherCustom("Stream Write+Sum equals Hash over same bytes", func(t *testing.T, h crypto.Hasher) {
			payload := []byte("the quick brown fox jumps over the lazy dog")
			s := h.NewStream()
			defer s.Close()
			_, _ = s.Write(payload)
			testkit.True(t, s.Sum().Equal(h.Hash(payload)),
				"Stream Write+Sum must equal Hash over the same bytes")
		}),

		HasherCustom("Stream split-Write equals single Write of concatenation", func(t *testing.T, h crypto.Hasher) {
			full := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
			s := h.NewStream()
			defer s.Close()
			_, _ = s.Write(full[:10])
			_, _ = s.Write(full[10:25])
			_, _ = s.Write(full[25:])
			testkit.True(t, s.Sum().Equal(h.Hash(full)),
				"split-Write must equal Hash over the concatenation")
		}),

		HasherCustom("Stream Reset clears state", func(t *testing.T, h crypto.Hasher) {
			s := h.NewStream()
			defer s.Close()
			_, _ = s.Write([]byte("first"))
			_ = s.Sum()
			s.Reset()
			_, _ = s.Write([]byte("second"))
			testkit.True(t, s.Sum().Equal(h.Hash([]byte("second"))),
				`Stream after Reset must equal Hash("second")`)
		}),

		HasherCustom("Stream Sum is non-resetting (snapshot only)", func(t *testing.T, h crypto.Hasher) {
			s := h.NewStream()
			defer s.Close()
			_, _ = s.Write([]byte("ab"))
			_ = s.Sum() // snapshot
			_, _ = s.Write([]byte("c"))
			testkit.True(t, s.Sum().Equal(h.Hash([]byte("abc"))),
				`Sum must snapshot only — must not reset state`)
		}),
	}
}

// otherWidthDigest returns a non-zero [crypto.Digest] whose width is
// not size, so a width precondition can be probed without a
// consumer-supplied fixture. The bytes are 0xAB rather than zero
// because an all-zero digest of the wrong width would still be
// refused, but for the reason the zero-Digest assertion already
// covers.
func otherWidthDigest(size int) crypto.Digest {
	if size == crypto.DigestSize256 {
		var b [crypto.DigestSize512]byte
		for i := range b {
			b[i] = 0xAB
		}

		return crypto.NewDigest512(b)
	}

	var b [crypto.DigestSize256]byte
	for i := range b {
		b[i] = 0xAB
	}

	return crypto.NewDigest256(b)
}

// HasherIDAssertion verifies [crypto.Hasher.ID] returns the
// expected stable build-local identifier.
func HasherIDAssertion(want crypto.ID) HasherOption {
	return HasherCustom("ID matches", func(t *testing.T, h crypto.Hasher) {
		testkit.Equal(t, h.ID(), want, "ID must match expected build-local identifier")
	})
}

// HasherAlgorithmAssertion verifies [crypto.Hasher.Algorithm]
// returns the expected long-term cross-build algorithm name.
func HasherAlgorithmAssertion(want crypto.Algorithm) HasherOption {
	return HasherCustom("Algorithm matches", func(t *testing.T, h crypto.Hasher) {
		testkit.Equal(t, h.Algorithm(), want, "Algorithm must match expected name")
	})
}

// HasherCrossStdlibAssertion verifies that [crypto.Hasher.Hash]
// produces byte-identical output to the supplied stdlib
// reference across a sweep of test inputs (empty, short, FIPS
// 180-4 §B-style two-block, and 4 KiB random-ish data).
//
// Lock byte-exact compatibility with the stdlib reference so the
// hash implementation cannot drift silently from the published
// algorithm.
func HasherCrossStdlibAssertion(stdlib func([]byte) []byte) HasherOption {
	return HasherCustom("Hash matches stdlib byte-for-byte", func(t *testing.T, h crypto.Hasher) {
		cases := []struct {
			name string
			data []byte
		}{
			{"empty", []byte{}},
			{`"abc"`, []byte("abc")},
			{
				"FIPS 180-4 §B-style two-block",
				[]byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
			},
			{"4 KiB 0xAB", bytes.Repeat([]byte{0xAB}, 4096)},
		}
		for _, tc := range cases {
			testkit.Equal(t, h.Hash(tc.data).Bytes(), stdlib(tc.data),
				tc.name+": Hash output must byte-match stdlib")
		}
	})
}

// HasherCombinePanicsOnSizeMismatch verifies [crypto.Hasher.Combine]
// panics when given digests whose [crypto.Digest.Size] does not
// match this Hasher's output size. The contract requires
// surfacing programmer errors rather than silently producing a
// truncated digest.
//
// The zero [crypto.Digest] is exempt — it is a documented sentinel
// rather than a programmer error, and is covered by
// [HasherCombineAdmitsZeroDigest].
//
// expectedSize is the Hasher's output size in bytes; the panic
// message must mention this number.
func HasherCombinePanicsOnSizeMismatch(expectedSize int, wrongSizeDigest crypto.Digest) HasherOption {
	return HasherCustom("Combine panics on size mismatch", func(t *testing.T, h crypto.Hasher) {
		testkit.False(t, wrongSizeDigest.IsZero(),
			"wrongSizeDigest must not be the zero Digest — that is an admitted sentinel")
		correct := h.Hash([]byte{}) // canonical correctly-sized digest
		testkit.Panics(t, func() { _ = h.Combine(wrongSizeDigest, correct) },
			"Combine(wrong-left, correct) must panic")
		testkit.Panics(t, func() { _ = h.Combine(correct, wrongSizeDigest) },
			"Combine(correct, wrong-right) must panic")
		testkit.Panics(t, func() { _ = h.Combine(wrongSizeDigest, wrongSizeDigest) },
			"Combine(wrong, wrong) must panic")
		_ = expectedSize // future use: assert panic message contains size info
	})
}

// HasherCombineAdmitsZeroDigest verifies [crypto.Hasher.Combine]
// accepts the zero [crypto.Digest] as either operand, zero-padded to
// this Hasher's digest width, per ADR-0007.
//
// The zero Digest is the documented sentinel for "no digest
// computed" — the predecessor anchor of a hash chain's genesis
// entry. Panicking on it would make the documentation a trap, so it
// is admitted while every other size mismatch still panics.
//
// zeroPadded must be a digest of this Hasher's own width whose bytes
// are all zero: the assertion checks that combining with the
// sentinel produces the same digest as combining with that value,
// which is what "zero-padded to the hasher's width" means.
func HasherCombineAdmitsZeroDigest(zeroPadded crypto.Digest) HasherOption {
	return HasherCustom("Combine admits the zero Digest", func(t *testing.T, h crypto.Hasher) {
		var zero crypto.Digest
		correct := h.Hash([]byte{})

		testkit.True(t, zero.IsZero(), "the zero Digest must report IsZero")
		testkit.Equal(t, zeroPadded.Size(), correct.Size(),
			"zeroPadded must match the hasher's digest width")

		// None of the Combine calls below may panic. A regression to
		// the old reject-everything behaviour surfaces as a panic
		// that fails this test directly, carrying the
		// implementation's own size-mismatch message.
		testkit.True(t, h.Combine(zero, correct).Equal(h.Combine(zeroPadded, correct)),
			"Combine(zero, x) must equal Combine(zero-padded, x)")
		testkit.True(t, h.Combine(correct, zero).Equal(h.Combine(correct, zeroPadded)),
			"Combine(x, zero) must equal Combine(x, zero-padded)")
		testkit.True(t, h.Combine(zero, zero).Equal(h.Combine(zeroPadded, zeroPadded)),
			"Combine(zero, zero) must equal Combine(zero-padded, zero-padded)")

		// The genesis digest must still be a well-formed digest of
		// this hasher's width, so a chain can keep combining from it.
		testkit.Equal(t, h.Combine(zero, correct).Size(), correct.Size(),
			"Combine with the sentinel must return a full-width digest")
	})
}
