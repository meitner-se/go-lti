package jwks

import (
	"container/list"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/meitner-se/go-lti/safehttp"
)

const (
	defaultTTL             = 15 * time.Minute
	defaultRefetchInterval = 30 * time.Second
	defaultTimeout         = 10 * time.Second
	defaultMaxEntries      = 1000

	// MaxBytes caps how much of a JWKS response is read.
	MaxBytes = 1 << 20
)

// ErrKeyNotFound is returned, wrapped, when a set has no key that matches the kid.
var ErrKeyNotFound = errors.New("jwks: no key matches the kid")

// Fetcher fetches and caches the JWKS that tools publish, for verifying the JWTs they sign.
//
// A fetched set is cached per URL for a TTL. A kid that the cached set doesn't have triggers a
// refetch, since that's how a tool rotates keys. Fetches for one URL happen at most once per
// refetch interval, so tokens with made-up kids or a tool whose JWKS is down can't make the
// Fetcher hammer it; a failed fetch is returned again until the interval has passed. Stale keys are
// never used when a fetch fails.
//
// Lookups for the same URL wait for one another and share one fetch; a waiting lookup gives up when
// its context ends. The cache holds about WithMaxEntries URLs and drops the least recently used,
// but never one being looked up or fetched within the refetch interval, so cache churn can't
// bypass the rate limit.
// It is safe for concurrent use.
type Fetcher struct {
	client          *http.Client
	ttl             time.Duration
	refetchInterval time.Duration
	maxEntries      int
	now             func() time.Time

	mu       sync.Mutex
	entries  map[string]*list.Element // of *entry
	lru      *list.List               // of *entry, most recently used first
	attempts map[string]attempt       // the last fetch per URL, which the rate limit reads
}

type entry struct {
	url string
	// lock is held while the entry is read or fetched. It is a channel so that a waiter can give up.
	lock      chan struct{}
	keys      []Key
	fetchedAt time.Time
}

type attempt struct {
	at  time.Time
	err error
}

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithTTL sets how long a fetched set is used before it is fetched again. It must be positive.
// The default is 15 minutes.
func WithTTL(ttl time.Duration) Option {
	return func(f *Fetcher) { f.ttl = ttl }
}

// WithRefetchInterval sets how soon a URL may be fetched again after a fetch, for an unknown kid
// or after a failure. It must be positive, and is lowered to the TTL when longer. The default is
// 30 seconds.
func WithRefetchInterval(interval time.Duration) Option {
	return func(f *Fetcher) { f.refetchInterval = interval }
}

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(f *Fetcher) { f.now = now }
}

// WithHTTPClient replaces the default safehttp client. Keep an SSRF guard in production: a tool
// chooses its jwks_uri. Tests use it to fetch from an httptest server on loopback.
func WithHTTPClient(client *http.Client) Option {
	return func(f *Fetcher) { f.client = client }
}

// WithMaxEntries sets how many URLs the cache holds, at least 1. URLs fetched within the refetch
// interval are kept even beyond it. The default is 1000.
func WithMaxEntries(n int) Option {
	return func(f *Fetcher) { f.maxEntries = n }
}

// NewFetcher returns a Fetcher that uses safehttp.NewClient with a 10 second timeout. It fails
// when an option is out of range.
func NewFetcher(opts ...Option) (*Fetcher, error) {
	f := &Fetcher{
		client:          safehttp.NewClient(defaultTimeout),
		ttl:             defaultTTL,
		refetchInterval: defaultRefetchInterval,
		maxEntries:      defaultMaxEntries,
		now:             time.Now,
		entries:         map[string]*list.Element{},
		lru:             list.New(),
		attempts:        map[string]attempt{},
	}

	for _, opt := range opts {
		opt(f)
	}

	switch {
	case f.ttl <= 0:
		return nil, errors.New("jwks: the ttl must be positive")
	case f.refetchInterval <= 0:
		return nil, errors.New("jwks: the refetch interval must be positive")
	case f.maxEntries < 1:
		return nil, errors.New("jwks: the cache must hold at least one entry")
	case f.client == nil || f.now == nil:
		return nil, errors.New("jwks: the http client and clock must not be nil")
	}

	// A set fetched within the refetch interval must still be fresh, or a valid kid would be
	// refused until the interval passed.
	f.refetchInterval = min(f.refetchInterval, f.ttl)

	return f, nil
}

// Key returns the public key with the given kid from the JWKS at jwksURI.
// An empty kid matches only when the set holds exactly one key.
// It returns an error wrapping ErrKeyNotFound when the set has no matching key, ctx's error when
// ctx ends while it waits, and any other error when the set couldn't be fetched.
func (f *Fetcher) Key(ctx context.Context, jwksURI, kid string) (*rsa.PublicKey, error) {
	e := f.entry(jwksURI)

	select {
	case e.lock <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-e.lock }()

	now := f.now()
	if !e.fetchedAt.IsZero() && now.Sub(e.fetchedAt) < f.ttl {
		if key, ok := findKey(e.keys, kid); ok {
			return key, nil
		}
	}

	if last, ok := f.lastAttempt(jwksURI); ok && now.Sub(last.at) < f.refetchInterval {
		if last.err != nil {
			return nil, last.err
		}

		// The last fetch succeeded within the interval, so the cached set is fresh and lacks the kid.
		return nil, ErrKeyNotFound
	}

	keys, err := f.fetch(ctx, jwksURI)
	if err != nil {
		// A caller giving up says nothing about the tool, so it must not block other callers.
		if ctx.Err() == nil {
			f.recordAttempt(jwksURI, attempt{at: now, err: err})
		}

		return nil, err
	}

	f.recordAttempt(jwksURI, attempt{at: now})
	e.keys = keys
	e.fetchedAt = now

	if key, ok := findKey(keys, kid); ok {
		return key, nil
	}

	return nil, ErrKeyNotFound
}

func (f *Fetcher) entry(jwksURI string) *entry {
	f.mu.Lock()
	defer f.mu.Unlock()

	if el, ok := f.entries[jwksURI]; ok {
		if e, ok := el.Value.(*entry); ok {
			f.lru.MoveToFront(el)

			return e
		}
	}

	e := &entry{url: jwksURI, lock: make(chan struct{}, 1)}
	f.entries[jwksURI] = f.lru.PushFront(e)
	f.evict()

	return e
}

// evict drops least recently used entries beyond maxEntries, skipping the newest entry, any entry
// a lookup holds, and any entry fetched within the refetch interval. f.mu must be held.
func (f *Fetcher) evict() {
	now := f.now()

	for el := f.lru.Back(); el != nil && f.lru.Len() > f.maxEntries; {
		prev := el.Prev()

		// A held entry may be mid-fetch, and dropping it would orphan the keys it is about to store.
		e, ok := el.Value.(*entry)
		if !ok || el == f.lru.Front() || len(e.lock) == 1 {
			el = prev

			continue
		}

		if last, attempted := f.attempts[e.url]; attempted && now.Sub(last.at) < f.refetchInterval {
			el = prev

			continue
		}

		f.lru.Remove(el)
		delete(f.entries, e.url)
		delete(f.attempts, e.url)

		el = prev
	}
}

func (f *Fetcher) lastAttempt(jwksURI string) (attempt, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	last, ok := f.attempts[jwksURI]

	return last, ok
}

func (f *Fetcher) recordAttempt(jwksURI string, a attempt) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.attempts[jwksURI] = a
}

func (f *Fetcher) fetch(ctx context.Context, jwksURI string) (keys []Key, err error) {
	u, err := url.Parse(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("jwks: cannot parse url: %w", err)
	}

	if err := safehttp.CheckURL(u); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("jwks: cannot build request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	res, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: cannot fetch set: %w", err)
	}

	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("jwks: cannot close response: %w", closeErr)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: set returned status %d", res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("jwks: cannot read set: %w", err)
	}

	if len(body) > MaxBytes {
		return nil, errors.New("jwks: set is larger than 1 MiB")
	}

	return ParseSet(body)
}

func findKey(keys []Key, kid string) (*rsa.PublicKey, bool) {
	if kid == "" {
		if len(keys) == 1 {
			return keys[0].PublicKey, true
		}

		return nil, false
	}

	for _, key := range keys {
		if key.ID == kid {
			return key.PublicKey, true
		}
	}

	return nil, false
}
