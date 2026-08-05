// Copyright Thesmos 2026
// SPDX-License-Identifier: Apache-2.0

// Package memory provides an in-process [cas.Store] for tests and
// local development — the role [go.thesmos.sh/core/crypto/localkey]
// plays for key custody. It is also the conformance suite's first
// subject, which is what keeps the CAS laws tested inside this
// module's own gates rather than deferred to the first external
// adapter.
//
// memory is for wiring tests and local runs only. Contents live in
// process memory with no durability, no capacity bound, and no
// eviction — an unbounded cache of everything ever put.
package memory

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"go.thesmos.sh/core/cas"
	"go.thesmos.sh/core/crypto"
	"go.thesmos.sh/core/errs"
)

// Sentinel causes for this implementation's failures.
//
// The seam's contract is the classification, not the cause: callers
// dispatch on [errs.Classify], and these sentinels are unexported
// because no consumer should couple to one implementation's
// spelling. They exist so this package's own tests can assert cause
// identity as well as class.
var (
	errZeroDigest = errors.New("memory: the zero digest is not an address")
	errMismatch   = errors.New("memory: data does not hash to the supplied address")
	errAbsent     = errors.New("memory: address not present")
)

// Store is a mutex-guarded in-memory [cas.Store].
//
// The map is keyed by [crypto.Digest] directly. The type is
// comparable by design, and its size participates in identity: a
// 256-bit and a 384-bit digest that share a byte prefix are
// distinct addresses, which a key built from the active bytes alone
// would collapse. Hashing the full struct per lookup is the price
// of that correctness, and in a test double it is the right trade.
//
// Both directions copy. Put clones data before storing, because the
// bytes were verified against the address at put time and an
// aliased caller slice mutated afterwards would silently break
// every future Get's integrity. Get clones on the way out, because
// the returned slice is the caller's per the seam contract.
//
// # Concurrency
//
// Safe for concurrent use. One mutex guards the map; holding it
// across the presence check and the insert is what makes the
// exactly-one-wrote law trivial rather than a compare-and-swap
// protocol. Contention is not this package's concern — it is a test
// double, and a production adapter makes its own locking argument.
//
// # Allocation contract
//
// One clone per Put and one per Get; Has allocates nothing. The
// verification hash on Put follows the bound [crypto.Hasher]'s own
// allocation contract, which is zero for every implementation in
// this module.
type Store struct {
	h  crypto.Hasher
	m  map[crypto.Digest][]byte
	mu sync.Mutex
}

// Compile-time interface check.
var _ cas.Store = (*Store)(nil)

// New returns an empty [Store] whose addresses are verified against
// h. The store is bound to h for its lifetime: one address space,
// one algorithm, per the seam contract.
func New(h crypto.Hasher) *Store {
	return &Store{h: h, m: map[crypto.Digest][]byte{}}
}

// Put stores data under its digest, verifying with the bound hasher
// that the digest of data equals d before anything is stored.
//
// Returns (true, nil) when the write happened, and (false, nil)
// when the address was already present — the idempotent no-op that
// makes retrying a Put safe and the signal that lets deduplication
// accounting exist at the seam. Under concurrent Puts of one
// address, exactly one caller observes true.
//
// Error modes, all leaving the store untouched:
//
//   - ctx already done — the context's error, unwrapped.
//   - d is the zero digest — classifies as [errs.Invalid]; the zero
//     [crypto.Digest] is the "no digest computed" sentinel, not an
//     address.
//   - digest(data) != d — classifies as [errs.Integrity]; storing
//     would let garbage be served under a trusted address to every
//     holder of d.
//
// # Allocation contract
//
// One clone of data on the written path; nothing on the duplicate
// or error paths.
func (s *Store) Put(ctx context.Context, d crypto.Digest, data []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if d.IsZero() {
		return false, errs.WithClass(errZeroDigest, errs.Invalid)
	}

	if !s.h.Hash(data).Equal(d) {
		return false, errs.WithClass(errMismatch, errs.Integrity)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.m[d]; ok {
		return false, nil
	}
	s.m[d] = bytes.Clone(data)

	return true, nil
}

// Get returns the bytes stored under d.
//
// The returned slice is the caller's: it is a copy, so neither the
// caller mutating it nor any later Put can affect the other. This
// implementation does not re-verify on read — the bytes were
// verified at put time and are unreachable for mutation afterwards,
// so a read-side check would re-prove an invariant the type system
// already holds.
//
// Error modes:
//
//   - ctx already done — the context's error, unwrapped.
//   - d is the zero digest — classifies as [errs.Invalid].
//   - d is absent — classifies as [errs.NotFound]; an address is
//     minted from bytes that existed, so absence here means the
//     caller holds an address this store never stored.
//
// # Allocation contract
//
// One clone of the stored bytes on success; nothing on error.
func (s *Store) Get(ctx context.Context, d crypto.Digest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if d.IsZero() {
		return nil, errs.WithClass(errZeroDigest, errs.Invalid)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	v, ok := s.m[d]
	if !ok {
		return nil, errs.WithClass(errAbsent, errs.NotFound)
	}

	return bytes.Clone(v), nil
}

// Has reports whether d is present, without transferring the body.
//
// Absence is a false report here, not an error — Has exists
// precisely to ask the question cheaply, and only the zero digest
// (classifying as [errs.Invalid]) or a done ctx produce errors.
//
// # Allocation contract
//
// Zero alloc.
func (s *Store) Has(ctx context.Context, d crypto.Digest) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if d.IsZero() {
		return false, errs.WithClass(errZeroDigest, errs.Invalid)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.m[d]

	return ok, nil
}
