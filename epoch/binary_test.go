// Copyright Thesmos 2026
// SPDX-License-Identifier: Apache-2.0

package epoch_test

import (
	"encoding"
	"testing"

	"go.thesmos.sh/testkit"

	"go.thesmos.sh/core/epoch"
)

// The encoding interfaces this package promises to satisfy; a
// missing method is a build failure, which is where it belongs.
var (
	_ encoding.BinaryAppender    = epoch.Zero
	_ encoding.BinaryMarshaler   = epoch.Zero
	_ encoding.BinaryUnmarshaler = (*epoch.Epoch)(nil)
)

func TestMarshalBinary(t *testing.T) {
	t.Parallel()

	t.Run("is eight bytes big-endian", func(t *testing.T) {
		t.Parallel()

		cases := map[string]struct {
			in   epoch.Epoch
			want []byte
		}{
			// The zero Epoch has a wire form: a freshly-created
			// scope legitimately persists it as its watermark seed.
			"zero": {epoch.Zero, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
			"one":  {1, []byte{0, 0, 0, 0, 0, 0, 0, 1}},
			"max": {
				^epoch.Epoch(0),
				[]byte{255, 255, 255, 255, 255, 255, 255, 255},
			},
			"mixed": {0x0102030405060708, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				got, err := tc.in.MarshalBinary()

				testkit.NoError(t, err, "MarshalBinary must succeed")
				testkit.Equal(t, got, tc.want,
					"the layout is a stable wire contract")
			})
		}
	})

	t.Run("AppendBinary appends rather than replaces", func(t *testing.T) {
		t.Parallel()

		got, err := epoch.Epoch(1).AppendBinary([]byte{0xAA})

		testkit.NoError(t, err, "AppendBinary must succeed")
		testkit.Equal(t, got, []byte{0xAA, 0, 0, 0, 0, 0, 0, 0, 1},
			"AppendBinary must extend dst")
	})
}

func TestUnmarshalBinary(t *testing.T) {
	t.Parallel()

	t.Run("round-trips every shape", func(t *testing.T) {
		t.Parallel()

		for _, want := range []epoch.Epoch{epoch.Zero, 1, 8, ^epoch.Epoch(0)} {
			b, err := want.MarshalBinary()
			testkit.NoError(t, err, "MarshalBinary must succeed")

			var got epoch.Epoch

			testkit.NoError(t, got.UnmarshalBinary(b),
				"UnmarshalBinary must accept its own output")
			testkit.Equal(t, got, want, "the round trip must be exact")
		}
	})

	t.Run("rejects any length but EpochSize", func(t *testing.T) {
		t.Parallel()

		cases := map[string][]byte{
			"nil":   nil,
			"empty": {},
			"short": {0, 0, 0, 0, 0, 0, 0},
			"long":  {0, 0, 0, 0, 0, 0, 0, 0, 0},
		}
		for name, data := range cases {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				got := epoch.Epoch(7)

				err := got.UnmarshalBinary(data)

				testkit.ErrorIs(t, err, epoch.ErrSize,
					"a wrong-length input must be a decode error")
				testkit.Equal(t, got, epoch.Epoch(7),
					"a rejected decode must not modify the receiver")
			})
		}
	})
}
