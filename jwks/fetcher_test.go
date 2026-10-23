package jwks

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test helper functions
// ============================================================================

// testJWKSServer serves whatever set it currently holds and counts requests.
type testJWKSServer struct {
	*httptest.Server

	mu       sync.Mutex
	body     []byte
	status   int
	requests atomic.Int32
}

func createTestJWKSServer(t *testing.T, keys ...Key) *testJWKSServer {
	t.Helper()

	s := &testJWKSServer{status: http.StatusOK}
	s.setKeys(t, keys...)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.requests.Add(1)

		s.mu.Lock()
		defer s.mu.Unlock()

		w.WriteHeader(s.status)
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.Close)

	return s
}

func (s *testJWKSServer) setKeys(t *testing.T, keys ...Key) {
	t.Helper()

	body, _ := json.Marshal(NewSet(keys...))

	s.mu.Lock()
	defer s.mu.Unlock()

	s.body = body
}

func (s *testJWKSServer) setResponse(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.status = status
	s.body = body
}

// testClock is a settable clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

func createTestFetcher(t *testing.T, server *testJWKSServer, clock *testClock, opts ...Option) *Fetcher {
	t.Helper()

	fetcher, err := NewFetcher(append([]Option{
		WithHTTPClient(server.Client()),
		WithClock(clock.Now),
		WithTTL(15 * time.Minute),
		WithRefetchInterval(30 * time.Second),
	}, opts...)...)
	require.NoError(t, err)

	return fetcher
}

func createTestRSAKey(t *testing.T, kid string) (Key, *rsa.PrivateKey) {
	t.Helper()

	private := createTestKey(t, 2048)

	return Key{ID: kid, PublicKey: &private.PublicKey}, private
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()

	body, err := json.Marshal(v)
	require.NoError(t, err)

	return body
}

// ============================================================================
// Tests
// ============================================================================

func TestFetcher_Key_CachesTheSet(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	server := createTestJWKSServer(t, key)
	clock := &testClock{now: time.Now()}
	fetcher := createTestFetcher(t, server, clock)

	for range 3 {
		got, err := fetcher.Key(t.Context(), server.URL, "kid-1")
		require.NoError(t, err)
		assert.True(t, key.PublicKey.Equal(got))
	}

	assert.Equal(t, int32(1), server.requests.Load())
}

func TestFetcher_Key_RefetchesAfterTheTTL(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	server := createTestJWKSServer(t, key)
	clock := &testClock{now: time.Now()}
	fetcher := createTestFetcher(t, server, clock)

	_, err := fetcher.Key(t.Context(), server.URL, "kid-1")
	require.NoError(t, err)

	clock.Advance(15 * time.Minute)

	_, err = fetcher.Key(t.Context(), server.URL, "kid-1")
	require.NoError(t, err)

	assert.Equal(t, int32(2), server.requests.Load())
}

func TestFetcher_Key_RefetchesOnAnUnknownKid(t *testing.T) {
	t.Parallel()

	oldKey, _ := createTestRSAKey(t, "old")
	newKey, _ := createTestRSAKey(t, "new")
	server := createTestJWKSServer(t, oldKey)
	clock := &testClock{now: time.Now()}
	fetcher := createTestFetcher(t, server, clock)

	_, err := fetcher.Key(t.Context(), server.URL, "old")
	require.NoError(t, err)

	// The tool rotates its key.
	server.setKeys(t, oldKey, newKey)
	clock.Advance(31 * time.Second)

	got, err := fetcher.Key(t.Context(), server.URL, "new")
	require.NoError(t, err)
	assert.True(t, newKey.PublicKey.Equal(got))
	assert.Equal(t, int32(2), server.requests.Load())
}

func TestFetcher_Key_LimitsRefetchesForUnknownKids(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	server := createTestJWKSServer(t, key)
	clock := &testClock{now: time.Now()}
	fetcher := createTestFetcher(t, server, clock)

	_, err := fetcher.Key(t.Context(), server.URL, "kid-1")
	require.NoError(t, err)

	for _, kid := range []string{"made-up-1", "made-up-2", "made-up-3"} {
		_, err := fetcher.Key(t.Context(), server.URL, kid)
		require.ErrorIs(t, err, ErrKeyNotFound)
	}

	assert.Equal(t, int32(1), server.requests.Load())

	clock.Advance(31 * time.Second)

	_, err = fetcher.Key(t.Context(), server.URL, "made-up-4")
	require.Error(t, err)
	assert.Equal(t, int32(2), server.requests.Load())
}

func TestFetcher_Key_EmptyKid(t *testing.T) {
	t.Parallel()

	first, _ := createTestRSAKey(t, "first")
	second, _ := createTestRSAKey(t, "second")

	t.Run("matches the only key", func(t *testing.T) {
		t.Parallel()

		server := createTestJWKSServer(t, first)
		fetcher := createTestFetcher(t, server, &testClock{now: time.Now()})

		got, err := fetcher.Key(t.Context(), server.URL, "")
		require.NoError(t, err)
		assert.True(t, first.PublicKey.Equal(got))
	})

	t.Run("is ambiguous with several keys", func(t *testing.T) {
		t.Parallel()

		server := createTestJWKSServer(t, first, second)
		fetcher := createTestFetcher(t, server, &testClock{now: time.Now()})

		_, err := fetcher.Key(t.Context(), server.URL, "")
		require.ErrorIs(t, err, ErrKeyNotFound)
	})
}

func TestFetcher_Key_BacksOffAfterAFailedFetch(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	server := createTestJWKSServer(t, key)
	server.setResponse(http.StatusServiceUnavailable, nil)
	clock := &testClock{now: time.Now()}
	fetcher := createTestFetcher(t, server, clock)

	for range 3 {
		_, err := fetcher.Key(t.Context(), server.URL, "kid-1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 503")
	}

	assert.Equal(t, int32(1), server.requests.Load())

	server.setResponse(http.StatusOK, mustMarshal(t, NewSet(key)))
	clock.Advance(31 * time.Second)

	_, err := fetcher.Key(t.Context(), server.URL, "kid-1")
	require.NoError(t, err)
	assert.Equal(t, int32(2), server.requests.Load())
}

func TestFetcher_Key_DoesNotUseStaleKeysWhenARefetchFails(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	server := createTestJWKSServer(t, key)
	clock := &testClock{now: time.Now()}
	fetcher := createTestFetcher(t, server, clock)

	_, err := fetcher.Key(t.Context(), server.URL, "kid-1")
	require.NoError(t, err)

	server.setResponse(http.StatusInternalServerError, nil)
	clock.Advance(15 * time.Minute)

	_, err = fetcher.Key(t.Context(), server.URL, "kid-1")
	require.Error(t, err)
}

func TestFetcher_Key_Rejects(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")

	tests := []struct {
		name    string
		status  int
		body    []byte
		message string
	}{
		{name: "a non-200 status", status: http.StatusNotFound, body: nil, message: "status 404"},
		{name: "a body over 1 MiB", status: http.StatusOK, body: []byte(`{"keys":[],"padding":"` + strings.Repeat("a", MaxBytes) + `"}`), message: "larger than 1 MiB"},
		{name: "a body that isn't a jwks", status: http.StatusOK, body: []byte(`<html>`), message: "cannot decode set"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := createTestJWKSServer(t, key)
			server.setResponse(tt.status, tt.body)
			fetcher := createTestFetcher(t, server, &testClock{now: time.Now()})

			_, err := fetcher.Key(t.Context(), server.URL, "kid-1")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.message)
		})
	}
}

func TestFetcher_Key_RejectsNonHTTPSURLs(t *testing.T) {
	t.Parallel()

	fetcher, err := NewFetcher()
	require.NoError(t, err)

	for _, raw := range []string{"http://tool.example.com/jwks", "ftp://tool.example.com/jwks", "not a url", ""} {
		_, err := fetcher.Key(t.Context(), raw, "kid-1")
		require.Error(t, err, raw)
		assert.NotErrorIs(t, err, ErrKeyNotFound, raw)
	}
}

func TestFetcher_Key_BoundsTheCache(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	server := createTestJWKSServer(t, key)
	clock := &testClock{now: time.Now()}
	fetcher := createTestFetcher(t, server, clock, WithMaxEntries(2))

	// Each lookup is a refetch interval after the last, so every earlier entry may be evicted.
	for _, path := range []string{"/a", "/b", "/a", "/c", "/a", "/b"} {
		_, err := fetcher.Key(t.Context(), server.URL+path, "kid-1")
		require.NoError(t, err)

		clock.Advance(31 * time.Second)
	}

	// /a stays cached because it was used most recently each time; /b was evicted by /c and refetched.
	assert.Equal(t, int32(4), server.requests.Load())
	assert.Len(t, fetcher.entries, 2)
}

func TestFetcher_Key_ConcurrentLookupsShareOneFetch(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	server := createTestJWKSServer(t, key)
	fetcher := createTestFetcher(t, server, &testClock{now: time.Now()})

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			_, err := fetcher.Key(t.Context(), server.URL, "kid-1")
			assert.NoError(t, err)
		})
	}

	wg.Wait()

	assert.Equal(t, int32(1), server.requests.Load())
}
