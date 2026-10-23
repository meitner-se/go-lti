// Package safehttp provides an HTTP client for fetching URLs that someone else controls, such as
// a tool's jwks_uri or logo, without letting them point it at your internal network.
package safehttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

const (
	dialTimeout           = 5 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	responseHeaderTimeout = 5 * time.Second
	maxRedirects          = 3
)

var (
	// ErrNonPublicAddress is returned, wrapped, when a request would connect to a non-public address.
	ErrNonPublicAddress = errors.New("safehttp: refusing to connect to a non-public address")
	// ErrNotHTTPS is returned, wrapped, for a URL that isn't an absolute https URL without credentials.
	ErrNotHTTPS = errors.New("safehttp: url must be an absolute https url without credentials")
	// ErrTooManyRedirects is returned, wrapped, after three redirects.
	ErrTooManyRedirects = errors.New("safehttp: too many redirects")
)

// ipv6GlobalUnicast is the only IPv6 range with public unicast addresses (RFC 4291 §2.4). Everything
// outside it, such as site-local fec0::/10, IPv4-compatible ::/96 and IPv4-translated
// ::ffff:0:0:0/96, is refused.
var ipv6GlobalUnicast = netip.MustParsePrefix("2000::/3")

// blockedPrefixes are special-purpose ranges that netip's predicates and ipv6GlobalUnicast don't
// cover (RFC 6890).
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, including broadcast
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments: Teredo, ORCHID, benchmarking
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4, which can embed a private IPv4 address
	netip.MustParsePrefix("3fff::/20"),       // documentation
}

// NewClient returns an HTTP client that guards against SSRF.
//
// It refuses to connect to loopback, private, link-local and other non-public addresses, and only
// follows https redirects, at most three of them. The address check runs on the IP each connection
// actually dials, after DNS resolution, so it also covers redirect targets and DNS rebinding.
// Proxies from the environment are ignored, since a proxy would hide the destination. timeout
// bounds the whole request including reading the body.
//
// Check the first URL with CheckURL before sending a request: the client checks the addresses it
// dials and the redirects it follows, not the scheme of the request it is given. Pass a non-zero
// timeout and cap the response body you read: the client limits neither on its own.
func NewClient(timeout time.Duration) *http.Client {
	return newClient(timeout, func(addr netip.AddrPort) bool { return IsPublicAddr(addr.Addr()) })
}

func newClient(timeout time.Duration, allowed func(netip.AddrPort) bool) *http.Client {
	dialer := &net.Dialer{
		Timeout: dialTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			addr, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("safehttp: cannot parse dialed address: %w", err)
			}

			if !allowed(addr) {
				return ErrNonPublicAddress
			}

			return nil
		},
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return ErrTooManyRedirects
			}

			return CheckURL(req.URL)
		},
	}
}

// IsPublicAddr reports whether addr is a globally routable unicast address.
func IsPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()

	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}

	if addr.Is6() && !ipv6GlobalUnicast.Contains(addr) {
		return false
	}

	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}

	return true
}

// CheckURL returns ErrNotHTTPS unless u is an absolute https URL without credentials.
func CheckURL(u *url.URL) error {
	if u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return ErrNotHTTPS
	}

	return nil
}
