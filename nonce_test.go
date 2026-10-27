package lti

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryNonceStore(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	store := NewMemoryNonceStore()
	store.now = func() time.Time { return now }

	claim := func(issuer, nonce string, expiresAt time.Time) bool {
		t.Helper()

		fresh, err := store.Claim(t.Context(), issuer, nonce, expiresAt)
		require.NoError(t, err)

		return fresh
	}

	assert.True(t, claim("client-1", "nonce-1", now.Add(time.Hour)))
	assert.False(t, claim("client-1", "nonce-1", now.Add(time.Hour)), "a used nonce is refused")
	assert.True(t, claim("client-2", "nonce-1", now.Add(time.Hour)), "nonces are per issuer")
	assert.True(t, claim("client-1\x00nonce-1", "", now.Add(time.Hour)), "issuer and nonce can't run together")

	now = now.Add(time.Hour)
	assert.True(t, claim("client-1", "nonce-1", now.Add(time.Minute)), "an expired nonce can be used again")
	assert.False(t, claim("client-1", "nonce-1", now.Add(time.Minute)))
}

func TestMemoryNonceStore_ForgetsExpiredNonces(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	store := NewMemoryNonceStore()
	store.now = func() time.Time { return now }

	for i := range 10 {
		_, err := store.Claim(t.Context(), "client-1", fmt.Sprintf("nonce-%d", i), now.Add(time.Duration(i+1)*time.Minute))
		require.NoError(t, err)
	}

	assert.Len(t, store.expiresAt, 10)

	now = now.Add(5 * time.Minute)
	_, err := store.Claim(t.Context(), "client-1", "nonce-new", now.Add(time.Hour))
	require.NoError(t, err)

	assert.Len(t, store.expiresAt, 6, "the five nonces that expired are forgotten")
}

func TestMemoryNonceStore_IsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	store := NewMemoryNonceStore()
	expiresAt := time.Now().Add(time.Hour)

	var (
		fresh atomic.Int64
		wg    sync.WaitGroup
	)

	for range 50 {
		wg.Go(func() {
			for i := range 20 {
				ok, err := store.Claim(t.Context(), "client-1", fmt.Sprintf("nonce-%d", i), expiresAt)
				assert.NoError(t, err)

				if ok {
					fresh.Add(1)
				}
			}
		})
	}

	wg.Wait()

	assert.Equal(t, int64(20), fresh.Load(), "each nonce is claimed exactly once")
}
