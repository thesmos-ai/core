// Copyright Thesmos 2026
// SPDX-License-Identifier: Apache-2.0

// Package cas is the content-addressed storage seam: a store whose
// keys ARE the digests of its values, so writes are idempotent,
// deduplication is inherent, and every read is verifiable against
// the address that requested it.
//
// # The kind
//
// cas answers the storage-kind discriminators as its own kind:
// absence is an error — an address is minted from bytes that
// existed; values are whole [][]byte, because the address is the
// digest of all the bytes and the writer must have hashed them
// before it can name the destination; the content mints the key;
// and nothing mutates after a write.
//
// Listing, TTLs, deletion, and metadata are deliberately absent. A
// digest space has no prefix structure to enumerate; expiry
// contradicts address-implies-availability; deletion is garbage
// collection over a reachability set only the consumer knows, and
// erasure of meaning is the encryption layer's job — encrypt, then
// shred the key via [go.thesmos.sh/core/crypto.Destroyer]; content
// identity paired with names or provenance is consumer vocabulary.
//
// # Failure semantics
//
// Every failure returns an error classifying under
// [go.thesmos.sh/core/errs.Classify]: a put whose data does not
// hash to its address is Integrity, an absent address on read is
// NotFound, and the zero [crypto.Digest] — which is a sentinel, not
// an address — is Invalid from every method.
package cas

import (
	"context"

	"go.thesmos.sh/core/crypto"
)

// Store is content-addressed storage over one hashing algorithm.
//
// The address is a [crypto.Digest] because a CAS address is a
// commitment, not a name. An assigned identifier — a
// [go.thesmos.sh/core/id.ID], a
// string key — is minted by someone and relates to its content by
// convention only; a digest is computed FROM the content, which is
// what makes Put's verification, idempotent writes, and verifiable
// reads expressible at all. A consumer that wants to NAME stored
// content keeps its own (name → digest) record beside this seam;
// naming and committing compose, and conflating them would reduce
// this store to a key-value seam with an unverifiable key.
//
// A Store is bound to exactly one [crypto.Hasher] at construction.
// One address space, one algorithm: a store that admitted two would
// give identical bytes two addresses, and deduplication — half the
// point of content addressing — would silently halve. An address
// produced by any other algorithm fails Put's verification and is
// absent for Get and Has.
//
// The zero [crypto.Digest] is not an address: it is the documented
// "no digest computed" sentinel — see [crypto.Digest.IsZero] — and
// every method rejects it with an error classifying as
// [go.thesmos.sh/core/errs.Invalid] before touching storage.
//
// # Fencing
//
// A Store implementation MAY be fenced: the fence epoch binds at
// handle construction and Put validates it atomically with the
// write, per the fence laws documented on
// [go.thesmos.sh/core/epoch.Admissible].
//
// # Concurrency
//
// Implementations must be safe for concurrent use. For concurrent
// Puts of the same address, exactly one reports wrote=true — the
// signal is an accounting primitive, and double-counting it
// double-charges whatever is metered against it.
type Store interface {
	// Put stores data under its digest. It MUST verify that the
	// bound hasher's digest of data equals d, and return an error
	// classifying as [go.thesmos.sh/core/errs.Integrity] — storing
	// nothing — when they disagree. Returns wrote=false, with no
	// error, when the address is already present: re-putting
	// identical bytes is the idempotent no-op that makes CAS
	// retry-safe.
	Put(ctx context.Context, d crypto.Digest, data []byte) (wrote bool, err error)

	// Get returns the bytes stored under d. The returned slice is
	// the caller's: implementations must not alias it to internal
	// storage, and later Puts must not affect it. An absent
	// address returns an error classifying as
	// [go.thesmos.sh/core/errs.NotFound].
	//
	// Implementations MAY re-verify the digest on read; one that
	// documents doing so is held to it by the conformance suite.
	Get(ctx context.Context, d crypto.Digest) ([]byte, error)

	// Has reports presence without transferring the body.
	Has(ctx context.Context, d crypto.Digest) (bool, error)
}
