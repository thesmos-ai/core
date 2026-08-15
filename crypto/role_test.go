// Copyright Thesmos 2026
// SPDX-License-Identifier: Apache-2.0

package crypto_test

import (
	"fmt"
	"testing"

	"go.thesmos.sh/testkit"

	"go.thesmos.sh/core/crypto"
)

func TestRole(t *testing.T) {
	t.Parallel()

	t.Run("the arity boundary is the high bit", func(t *testing.T) {
		t.Parallel()

		// The exact boundary is the contract, not an implementation
		// detail: a protocol assigns role bytes once and writes them
		// into persisted digests, so moving 0x80 later would silently
		// reclassify a registry that is already on disk.
		cases := map[crypto.Role]bool{
			0x00: true,
			0x01: true,
			0x7E: true,
			0x7F: true,
			0x80: false,
			0x81: false,
			0xFE: false,
			0xFF: false,
		}
		for role, unary := range cases {
			testkit.Equal(t, role.IsUnary(), unary,
				fmt.Sprintf("role %#02x IsUnary must be %v", byte(role), unary))
			testkit.Equal(t, role.IsBinary(), !unary,
				fmt.Sprintf("role %#02x IsBinary must be %v", byte(role), !unary))
		}
	})

	t.Run("every role is exactly one arity", func(t *testing.T) {
		t.Parallel()

		// Exhaustive over the whole space, because the guarantee the
		// methods rest on is total: a role that were neither — or
		// both — would let one byte reach both operations, which is
		// the collision the split exists to prevent.
		for i := range 256 {
			role := crypto.Role(i)
			testkit.False(t, role.IsUnary() == role.IsBinary(),
				fmt.Sprintf("role %#02x must be unary or binary, never both or neither", i))
		}
	})

	t.Run("the halves are the same size", func(t *testing.T) {
		t.Parallel()

		unary := 0
		for i := range 256 {
			if crypto.Role(i).IsUnary() {
				unary++
			}
		}
		testkit.Equal(t, unary, 128,
			"the arity split must leave 128 roles per half")
	})
}
