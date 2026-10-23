package safehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test helper functions
// ============================================================================

// createTestGuardedClient returns a guarded client that trusts httptest's certificate and treats
// only the given server's address as public, so redirects to any other address count as internal.
func createTestClient(t *testing.T, public *httptest.Server) *http.Client {
	t.Helper()

	publicAddr := netip.MustParseAddrPort(public.Listener.Addr().String())
	client := newClient(5*time.Second, func(addr netip.AddrPort) bool { return addr == publicAddr })

	roots := x509.NewCertPool()
	roots.AddCert(public.Certificate())

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)

	transport.TLSClientConfig.RootCAs = roots

	return client
}

func get(ctx context.Context, client *http.Client, target string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	return res.Body.Close()
}

func redirectTo(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	})
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// ============================================================================
// Tests
// ============================================================================

func TestIsPublicAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr   string
		public bool
	}{
		{addr: "93.184.215.14", public: true},
		{addr: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", public: true},
		{addr: "127.0.0.1", public: false},
		{addr: "::1", public: false},
		{addr: "10.1.2.3", public: false},
		{addr: "172.16.0.1", public: false},
		{addr: "192.168.1.1", public: false},
		{addr: "fd00::1", public: false},
		{addr: "169.254.169.254", public: false},
		{addr: "fe80::1", public: false},
		{addr: "0.0.0.0", public: false},
		{addr: "::", public: false},
		{addr: "100.64.0.1", public: false},
		{addr: "224.0.0.1", public: false},
		{addr: "255.255.255.255", public: false},
		{addr: "198.18.0.1", public: false},
		{addr: "::ffff:127.0.0.1", public: false},
		{addr: "::ffff:10.0.0.1", public: false},
		{addr: "64:ff9b::a00:1", public: false},
		{addr: "2002:a00:1::", public: false},
		{addr: "0.1.2.3", public: false},
		{addr: "240.0.0.1", public: false},
		{addr: "192.88.99.1", public: false},
		{addr: "::ffff:100.64.0.1", public: false},
		{addr: "::ffff:93.184.215.14", public: true},
		{addr: "fec0::1", public: false},
		{addr: "::7f00:1", public: false},
		{addr: "::a00:1", public: false},
		{addr: "::ffff:0:7f00:1", public: false},
		{addr: "2001::1", public: false},
		{addr: "2001:10::1", public: false},
		{addr: "2001:2::1", public: false},
		{addr: "5f00::1", public: false},
		{addr: "3fff::1", public: false},
		{addr: "2a00:1450:4001:830::200e", public: true},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.public, IsPublicAddr(netip.MustParseAddr(tt.addr)))
		})
	}
}

func TestNewClient_RefusesLoopback(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(okHandler())
	t.Cleanup(server.Close)

	err := get(t.Context(), NewClient(5*time.Second), server.URL)

	require.ErrorIs(t, err, ErrNonPublicAddress)
}

func TestNewClient_RefusesLoopbackBehindAHostName(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(okHandler())
	t.Cleanup(server.Close)

	// localhost resolves to a loopback address, which the dial check sees after resolution.
	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	u.Host = "localhost:" + u.Port()

	err = get(t.Context(), NewClient(5*time.Second), u.String())

	require.ErrorIs(t, err, ErrNonPublicAddress)
}

func TestNewClient_FollowsHTTPSRedirectToAPublicAddress(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, server.URL+"/end", http.StatusFound)

			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	require.NoError(t, get(t.Context(), createTestClient(t, server), server.URL+"/start"))
}

func TestNewClient_RefusesRedirectToAnInternalAddress(t *testing.T) {
	t.Parallel()

	internal := httptest.NewTLSServer(okHandler())
	t.Cleanup(internal.Close)

	public := httptest.NewTLSServer(redirectTo(internal.URL))
	t.Cleanup(public.Close)

	err := get(t.Context(), createTestClient(t, public), public.URL)

	require.ErrorIs(t, err, ErrNonPublicAddress)
}

func TestNewClient_RefusesRedirectToHTTP(t *testing.T) {
	t.Parallel()

	public := httptest.NewTLSServer(redirectTo("http://tool.example.com/jwks"))
	t.Cleanup(public.Close)

	err := get(t.Context(), createTestClient(t, public), public.URL)

	require.ErrorIs(t, err, ErrNotHTTPS)
}

func TestNewClient_StopsAfterThreeRedirects(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL+r.URL.Path+"x", http.StatusFound)
	}))
	t.Cleanup(server.Close)

	err := get(t.Context(), createTestClient(t, server), server.URL+"/")

	require.ErrorIs(t, err, ErrTooManyRedirects)
}

func TestNewClient_TimesOut(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	client := createTestClient(t, server)
	client.Timeout = 100 * time.Millisecond

	err := get(t.Context(), client, server.URL)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Client.Timeout")
}

func TestCheckURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw string
		ok  bool
	}{
		{raw: "https://tool.example.com/jwks", ok: true},
		{raw: "http://tool.example.com/jwks", ok: false},
		{raw: "file:///etc/passwd", ok: false},
		{raw: "https:///jwks", ok: false},
		{raw: "https://user:pass@tool.example.com/jwks", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			t.Parallel()

			u, err := url.Parse(tt.raw)
			require.NoError(t, err)

			err = CheckURL(u)
			if tt.ok {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrNotHTTPS)
		})
	}
}

func TestNewClient_FollowsExactlyThreeRedirects(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops := len(r.URL.Path) - 1
		if hops < 3 || r.URL.Query().Get("stop") == "" {
			http.Redirect(w, r, server.URL+r.URL.Path+"x?"+r.URL.RawQuery, http.StatusFound)

			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	// /?stop=1 redirects to /x, /xx and /xxx, then answers: three redirects.
	require.NoError(t, get(t.Context(), createTestClient(t, server), server.URL+"/?stop=1"))

	// Without stop the chain never ends, and the fourth redirect is refused.
	require.ErrorIs(t, get(t.Context(), createTestClient(t, server), server.URL+"/"), ErrTooManyRedirects)
}

func TestNewClient_Configuration(t *testing.T) {
	t.Parallel()

	client := NewClient(7 * time.Second)
	assert.Equal(t, 7*time.Second, client.Timeout)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, transport.Proxy, "a proxy would hide the destination from the dial check")
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
}
