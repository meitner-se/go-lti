package jwks

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti/safehttp"
)

// ============================================================================
// Test helper functions
// ============================================================================

// createTestModulusJWK returns an RS256 JWK whose modulus has exactly bits bits. ParseSet doesn't
// check primality, so a random odd number stands in for a real key of any size.
func createTestModulusJWK(t *testing.T, kid string, bits int, e *big.Int) JWK {
	t.Helper()

	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	require.NoError(t, err)

	n.SetBit(n, bits-1, 1)
	n.SetBit(n, 0, 1)

	return JWK{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid, N: base64.RawURLEncoding.EncodeToString(n.Bytes()), E: base64.RawURLEncoding.EncodeToString(e.Bytes())}
}

// entryHeld reports whether a lookup currently holds the cache entry for jwksURI.
func entryHeld(f *Fetcher, jwksURI string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	el, ok := f.entries[jwksURI]
	if !ok {
		return false
	}

	e, ok := el.Value.(*entry)

	return ok && len(e.lock) == 1
}

// ============================================================================
// Tests
// ============================================================================

func TestRegression_HugeModulusIsNotUsable(t *testing.T) {
	t.Parallel()

	_, err := ParseSet(createTestSetJSON(t, createTestModulusJWK(t, "big", 8192, big.NewInt(65537))))
	require.ErrorIs(t, err, ErrNoSigningKeys)
}

func TestRegression_KeySizeAndExponentBounds(t *testing.T) {
	t.Parallel()

	e := big.NewInt(65537)

	tests := []struct {
		name   string
		key    JWK
		usable bool
	}{
		{name: "2047 bits", key: createTestModulusJWK(t, "k", 2047, e), usable: false},
		{name: "2048 bits", key: createTestModulusJWK(t, "k", 2048, e), usable: true},
		{name: "4096 bits", key: createTestModulusJWK(t, "k", 4096, e), usable: true},
		{name: "4097 bits", key: createTestModulusJWK(t, "k", 4097, e), usable: false},
		{name: "exponent 1", key: createTestModulusJWK(t, "k", 2048, big.NewInt(1)), usable: false},
		{name: "exponent 3", key: createTestModulusJWK(t, "k", 2048, big.NewInt(3)), usable: true},
		{name: "exponent 2^31+1", key: createTestModulusJWK(t, "k", 2048, big.NewInt(1<<31+1)), usable: false},
		{name: "exponent 2^31-1", key: createTestModulusJWK(t, "k", 2048, big.NewInt(1<<31-1)), usable: true},
		{name: "exponent 2^64+65537", key: createTestModulusJWK(t, "k", 2048, new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(65537))), usable: false},
		{name: "exponent beyond int64", key: createTestModulusJWK(t, "k", 2048, new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 70), big.NewInt(1))), usable: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keys, err := ParseSet(createTestSetJSON(t, tt.key))
			if tt.usable {
				require.NoError(t, err)
				assert.Len(t, keys, 1)

				return
			}

			require.ErrorIs(t, err, ErrNoSigningKeys)
		})
	}
}

func TestRegression_UnusableKeysAreSkippedNextToAGoodOne(t *testing.T) {
	t.Parallel()

	good := NewSet(Key{ID: "good", PublicKey: &createTestKey(t, 2048).PublicKey}).Keys[0]

	malformed := good
	malformed.Kid = "malformed"
	malformed.N = "not base64!"

	padded := good
	padded.Kid = "padded"
	padded.N += "=="

	short := createTestModulusJWK(t, "short", 1024, big.NewInt(65537))
	huge := createTestModulusJWK(t, "huge", 8192, big.NewInt(65537))
	evenE := createTestModulusJWK(t, "even", 2048, big.NewInt(65536))

	// 3072 bits is 512 base64 characters exactly, so the decoder returns the whole modulus with its error.
	trailing := createTestModulusJWK(t, "trailing", 3072, big.NewInt(65537))
	trailing.N += "!!!!"

	notRSA := good
	notRSA.Kid = "not-rsa"
	notRSA.Kty = "oct"

	keys, err := ParseSet(createTestSetJSON(t, malformed, padded, short, huge, evenE, trailing, notRSA, good))
	require.NoError(t, err)

	require.Len(t, keys, 1)
	assert.Equal(t, "good", keys[0].ID)
}

func TestRegression_TTLShorterThanRefetchInterval(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	server := createTestJWKSServer(t, key)
	clock := &testClock{now: time.Now()}
	fetcher, err := NewFetcher(WithHTTPClient(server.Client()), WithClock(clock.Now), WithTTL(10*time.Second))
	require.NoError(t, err)

	_, err = fetcher.Key(t.Context(), server.URL, "kid-1")
	require.NoError(t, err)

	clock.Advance(15 * time.Second)

	_, err = fetcher.Key(t.Context(), server.URL, "kid-1")
	require.NoError(t, err, "a valid kid must not turn into ErrKeyNotFound after the TTL")
	assert.Equal(t, int32(2), server.requests.Load())
}

func TestRegression_CacheChurnKeepsTheRateLimit(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	server := createTestJWKSServer(t, key)
	fetcher := createTestFetcher(t, server, &testClock{now: time.Now()}, WithMaxEntries(2))

	for i := range 50 {
		_, err := fetcher.Key(t.Context(), server.URL+"/victim", "unknown-kid")
		require.ErrorIs(t, err, ErrKeyNotFound)

		for _, other := range []int{i % 2, (i + 1) % 2} {
			_, err := fetcher.Key(t.Context(), fmt.Sprintf("%s/other%d", server.URL, other), "kid-1")
			require.NoError(t, err)
		}
	}

	assert.Equal(t, int32(3), server.requests.Load(), "each url is fetched once per refetch interval, however the cache churns")
}

func TestRegression_AWaiterGivesUpWhenItsContextEnds(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	fetcher, err := NewFetcher(WithHTTPClient(server.Client()))
	require.NoError(t, err)

	go func() {
		_, _ = fetcher.Key(context.Background(), server.URL, "kid-1")
	}()

	require.Eventually(t, func() bool { return entryHeld(fetcher, server.URL) }, time.Second, 5*time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = fetcher.Key(ctx, server.URL, "kid-1")

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), time.Second)
}

func TestRegression_ACancelledCallerDoesNotBlockOthers(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	body, _ := json.Marshal(NewSet(key))
	ctx, cancel := context.WithCancel(t.Context())

	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			// The first caller gives up while its fetch is in flight.
			cancel()
			<-r.Context().Done()

			return
		}

		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	fetcher, err := NewFetcher(WithHTTPClient(server.Client()))
	require.NoError(t, err)

	_, err = fetcher.Key(ctx, server.URL, "kid-1")
	require.Error(t, err)

	_, err = fetcher.Key(t.Context(), server.URL, "kid-1")
	require.NoError(t, err, "the cancelled lookup's error must not be served to the next caller")
	assert.Equal(t, int32(2), requests.Load())
}

func TestRegression_FetcherRefusesAPlainHTTPURL(t *testing.T) {
	t.Parallel()

	key, _ := createTestRSAKey(t, "kid-1")
	body, _ := json.Marshal(NewSet(key))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	fetcher, err := NewFetcher(WithHTTPClient(server.Client()))
	require.NoError(t, err)

	_, err = fetcher.Key(t.Context(), server.URL, "kid-1")
	require.ErrorIs(t, err, safehttp.ErrNotHTTPS, "the url is checked even when the client would connect")
}

func TestRegression_FetcherStopsReadingAnOversizedSet(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(make([]byte, MaxBytes+1))
		assert.NoError(t, err)

		// The body never ends, so only a capped read returns.
		w.(http.Flusher).Flush()
		<-release
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	fetcher, err := NewFetcher(WithHTTPClient(server.Client()))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err = fetcher.Key(ctx, server.URL, "kid-1")
	require.ErrorContains(t, err, "larger than 1 MiB")
}

func TestRegression_NewFetcherValidatesOptions(t *testing.T) {
	t.Parallel()

	for name, opt := range map[string]Option{
		"a zero ttl":              WithTTL(0),
		"a negative ttl":          WithTTL(-time.Second),
		"a zero refetch interval": WithRefetchInterval(0),
		"no cache entries":        WithMaxEntries(0),
		"a nil http client":       WithHTTPClient(nil),
		"a nil clock":             WithClock(nil),
	} {
		_, err := NewFetcher(opt)
		require.Error(t, err, name)
	}

	fetcher, err := NewFetcher(WithTTL(10*time.Second), WithRefetchInterval(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, fetcher.refetchInterval, "the refetch interval is lowered to the ttl")
}
