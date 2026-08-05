// Copyright Thesmos 2026
// SPDX-License-Identifier: Apache-2.0

package memory_test

import (
	"testing"

	"go.thesmos.sh/testkit"

	"go.thesmos.sh/core/cas"
	"go.thesmos.sh/core/cas/memory"
	"go.thesmos.sh/core/coretest/castest"
	"go.thesmos.sh/core/crypto"
	"go.thesmos.sh/core/crypto/sha256"
)

func TestMemoryStoreConformance(t *testing.T) {
	t.Parallel()

	castest.AssertStore(t, func(h crypto.Hasher) cas.Store {
		return memory.New(h)
	})
}

func TestPut(t *testing.T) {
	t.Parallel()

	t.Run("clones its input", func(t *testing.T) {
		t.Parallel()

		// Implementation contract beyond the seam: the bytes were
		// verified against the address at put time, so a caller
		// mutating its slice afterwards must not be able to corrupt
		// what future readers receive.
		h := sha256.New()
		s := memory.New(h)

		data := []byte("verified at put time")
		d := h.Hash(data)

		wrote, err := s.Put(t.Context(), d, data)
		testkit.NoError(t, err, "Put must succeed")
		testkit.True(t, wrote, "the first Put must write")

		data[0] ^= 0xFF

		got, err := s.Get(t.Context(), d)
		testkit.NoError(t, err, "Get must succeed after the caller mutation")
		testkit.Equal(t, got, []byte("verified at put time"),
			"a caller mutating its input after Put must not reach the store")
		testkit.True(t, h.Hash(got).Equal(d),
			"what the store serves must still hash to its address")
	})
}
