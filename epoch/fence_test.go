// Copyright Thesmos 2026
// SPDX-License-Identifier: Apache-2.0

package epoch_test

import (
	"maps"
	"sync"
	"testing"

	"go.thesmos.sh/testkit"

	"go.thesmos.sh/core/coretest/epochtest"
	"go.thesmos.sh/core/epoch"
)

func TestAdmissible(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		w, e epoch.Epoch
		want bool
	}{
		"above the watermark":       {5, 6, true},
		"equal to the watermark":    {5, 5, true},
		"below the watermark":       {5, 4, false},
		"zero bypasses":             {5, epoch.Zero, true},
		"zero watermark admits all": {epoch.Zero, 1, true},
		"both zero":                 {epoch.Zero, epoch.Zero, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testkit.Equal(t, epoch.Admissible(tc.w, tc.e), tc.want,
				"Admissible must apply the admit-equal law")
		})
	}
}

func TestWatermark(t *testing.T) {
	t.Parallel()

	t.Run("admits and advances above the seed", func(t *testing.T) {
		t.Parallel()

		w := epoch.NewWatermark(3)

		testkit.NoError(t, w.Admit(5), "a later epoch must be admitted")
		testkit.Equal(t, w.Current(), epoch.Epoch(5),
			"an admitted later epoch must advance the watermark")
	})

	t.Run("admits an equal epoch without advancing", func(t *testing.T) {
		t.Parallel()

		// Admit-equal is load-bearing: one tenure performs many
		// writes, and a multi-write operation reuses one fence.
		w := epoch.NewWatermark(5)

		testkit.NoError(t, w.Admit(5), "the current epoch must stay admitted")
		testkit.Equal(t, w.Current(), epoch.Epoch(5),
			"an equal admit must not move the watermark")
	})

	t.Run("rejects a superseded epoch", func(t *testing.T) {
		t.Parallel()

		w := epoch.NewWatermark(5)

		testkit.ErrorIs(t, w.Admit(4), epoch.ErrFenced,
			"an epoch behind the watermark must be fenced")
		testkit.Equal(t, w.Current(), epoch.Epoch(5),
			"a rejected admit must not move the watermark")
	})

	t.Run("zero neither validates nor advances", func(t *testing.T) {
		t.Parallel()

		w := epoch.NewWatermark(5)

		testkit.NoError(t, w.Admit(epoch.Zero),
			"an unfenced write must be admitted unconditionally")
		testkit.Equal(t, w.Current(), epoch.Epoch(5),
			"an unfenced admit must not touch the watermark")
	})

	t.Run("the seed is the authority after construction", func(t *testing.T) {
		t.Parallel()

		// The reseed law: a watermark reconstructed from durable
		// state admits nothing it rejected before.
		w := epoch.NewWatermark(8)

		testkit.Equal(t, w.Current(), epoch.Epoch(8),
			"Current must report the seed before any admit")
		testkit.ErrorIs(t, w.Admit(7), epoch.ErrFenced,
			"a zombie below the seed must be fenced from the first admit")
	})

	t.Run("concurrent admits converge on the highest epoch", func(t *testing.T) {
		t.Parallel()

		const highest = 64

		w := epoch.NewWatermark(0)

		var wg sync.WaitGroup
		for e := epoch.Epoch(1); e <= highest; e++ {
			wg.Go(func() {
				// Racing authorities: lower epochs may be fenced
				// depending on interleaving — that is the fence
				// working — but no update may be lost.
				_ = w.Admit(e)
			})
		}
		wg.Wait()

		testkit.Equal(t, w.Current(), epoch.Epoch(highest),
			"the watermark must converge on the highest admitted epoch")
	})
}

// fencedStore is the reference fenced writer: a toy keyed store
// whose every write validates its handle's epoch against a durable
// watermark, atomically under one lock. It exists to be the first
// subject of epochtest.AssertFencedWriter.
type fencedStore struct {
	mu   sync.Mutex
	wm   *epoch.Watermark
	data map[string]string
}

type fencedHandle struct {
	s *fencedStore
	e epoch.Epoch
}

func (s *fencedStore) open(e epoch.Epoch) fencedHandle {
	return fencedHandle{s: s, e: e}
}

func (h fencedHandle) set(k, v string) error {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()

	if err := h.s.wm.Admit(h.e); err != nil {
		return err
	}
	h.s.data[k] = v

	return nil
}

func (h fencedHandle) clear(k string) error {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()

	if err := h.s.wm.Admit(h.e); err != nil {
		return err
	}
	delete(h.s.data, k)

	return nil
}

func TestFencedWriterConformance(t *testing.T) {
	t.Parallel()

	epochtest.AssertFencedWriter(t, epochtest.FencedSystem[fencedHandle]{
		NewScope: func() epochtest.FencedScope[fencedHandle] {
			s := &fencedStore{wm: epoch.NewWatermark(0), data: map[string]string{}}

			return epochtest.FencedScope[fencedHandle]{
				Open: func(e epoch.Epoch) (fencedHandle, error) {
					return s.open(e), nil
				},
				Supersede: func(e epoch.Epoch) {
					s.mu.Lock()
					defer s.mu.Unlock()
					_ = s.wm.Admit(e)
				},
				Snapshot: func() any {
					s.mu.Lock()
					defer s.mu.Unlock()

					return maps.Clone(s.data)
				},
			}
		},
		Writes: map[string]func(fencedHandle) error{
			"set":   func(h fencedHandle) error { return h.set("k", "v") },
			"clear": func(h fencedHandle) error { return h.clear("k") },
		},
	})
}
