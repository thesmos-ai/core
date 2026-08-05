// Copyright Thesmos 2026
// SPDX-License-Identifier: Apache-2.0

package epoch

import "encoding/binary"

// EpochSize is the width in bytes of the binary encoding.
const EpochSize = 8

// AppendBinary appends the canonical [EpochSize]-byte big-endian
// encoding of e to dst.
//
// The encoding is a stable wire contract (RFC-0014): a persisted
// watermark or a fence carried in a message must read back
// identically across builds and years; the layout will not change
// within a major version. The zero [Epoch] has a wire form — it is
// the number zero, and a freshly-created scope legitimately persists
// it as its watermark seed.
//
// Implements [encoding.BinaryAppender].
//
// # Allocation contract
//
// Zero alloc when dst has capacity for [EpochSize] more bytes.
func (e Epoch) AppendBinary(dst []byte) ([]byte, error) {
	return binary.BigEndian.AppendUint64(dst, uint64(e)), nil
}

// MarshalBinary returns the canonical [EpochSize]-byte encoding of
// e. Implements [encoding.BinaryMarshaler]; see [Epoch.AppendBinary]
// for the layout and the contract.
func (e Epoch) MarshalBinary() ([]byte, error) {
	return e.AppendBinary(make([]byte, 0, EpochSize))
}

// UnmarshalBinary sets e from the canonical encoding.
//
// Returns [ErrSize] unless len(data) is exactly [EpochSize]. A
// truncated read is a decode error, never a panic and never a
// partial value: e is left unmodified when data is rejected.
//
// Implements [encoding.BinaryUnmarshaler].
func (e *Epoch) UnmarshalBinary(data []byte) error {
	if len(data) != EpochSize {
		return ErrSize
	}

	*e = Epoch(binary.BigEndian.Uint64(data))

	return nil
}
