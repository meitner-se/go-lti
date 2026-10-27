package lti

import (
	"context"
	"sync"
	"time"
)

// nonceSweepInterval is how often a MemoryNonceStore forgets every expired nonce.
const nonceSweepInterval = time.Minute

// MemoryNonceStore is a NonceStore that remembers nonces in this process until they expire. It is
// safe for concurrent use.
//
// It isn't shared between processes or replicas, so a message replayed to another replica, or
// after a restart, is accepted again. Use it with a single replica, or when something else makes a
// message count once, such as a platform that only accepts one Deep Linking response per request.
type MemoryNonceStore struct {
	mu        sync.Mutex
	expiresAt map[memoryNonce]time.Time
	nextSweep time.Time
	now       func() time.Time
}

type memoryNonce struct {
	issuer string
	nonce  string
}

// NewMemoryNonceStore returns an empty MemoryNonceStore.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{expiresAt: map[memoryNonce]time.Time{}, now: time.Now}
}

// Claim marks nonce as used by issuer until expiresAt. It returns false when it was already used
// and hasn't expired.
func (s *MemoryNonceStore) Claim(_ context.Context, issuer, nonce string, expiresAt time.Time) (bool, error) {
	key := memoryNonce{issuer: issuer, nonce: nonce}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweep(now)

	if until, used := s.expiresAt[key]; used && until.After(now) {
		return false, nil
	}

	s.expiresAt[key] = expiresAt

	return true, nil
}

// sweep forgets every expired nonce, at most once per nonceSweepInterval.
func (s *MemoryNonceStore) sweep(now time.Time) {
	if now.Before(s.nextSweep) {
		return
	}

	for key, until := range s.expiresAt {
		if !until.After(now) {
			delete(s.expiresAt, key)
		}
	}

	s.nextSweep = now.Add(nonceSweepInterval)
}
