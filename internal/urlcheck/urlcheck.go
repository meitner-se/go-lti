// Package urlcheck holds the URL and domain checks that several go-lti packages share.
package urlcheck

import (
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ParseHTTPS parses raw and reports whether it is an absolute https URL without credentials, whose
// host is an ASCII host name or an IP address. Internationalized names must be given in their
// ASCII (punycode) form: a non-ASCII host can be read differently by other URL parsers.
func ParseHTTPS(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || !isHost(u.Host, u.Hostname()) {
		return nil, false
	}

	return u, true
}

// IsHTTPS reports whether raw is an absolute https URL without credentials.
func IsHTTPS(raw string) bool {
	_, ok := ParseHTTPS(raw)

	return ok
}

// OnDomains reports whether raw is an https URL whose host is one of domains or a subdomain of
// one. Domains that aren't valid domains, or are public suffixes, never match.
func OnDomains(raw string, domains []string) bool {
	u, ok := ParseHTTPS(raw)
	if !ok {
		return false
	}

	host := NormalizeDomain(u.Hostname())
	for _, domain := range domains {
		domain = NormalizeDomain(domain)
		if !IsDomain(domain) {
			continue
		}

		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

// NormalizeDomain trims spaces, lowercases, and drops a numeric port and a trailing dot. Anything
// else, such as a scheme or a path, is kept, so that IsDomain can refuse it.
func NormalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))

	if host, port, err := net.SplitHostPort(domain); err == nil && port != "" && isDigits(port) {
		domain = host
	}

	return strings.TrimSuffix(domain, ".")
}

// IsDomain reports whether domain is a bare ASCII host name, not an IP address and not a public
// suffix, so that matching subdomains of it can't cover other sites, such as everything under
// co.uk or github.io. A scheme, port, path or wildcard makes it invalid.
func IsDomain(domain string) bool {
	if domain == "" || domain != strings.TrimSuffix(domain, ".") || !isHostName(domain) {
		return false
	}

	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}

	return !IsPublicSuffix(domain)
}

// IsPublicSuffix reports whether domain is a suffix under which unrelated parties register names,
// from both the ICANN and the private sections of the Public Suffix List. A domain the list
// doesn't know, such as a bare "localhost", counts as one.
func IsPublicSuffix(domain string) bool {
	domain = NormalizeDomain(domain)
	suffix, _ := publicsuffix.PublicSuffix(domain)

	return suffix == domain
}

// isHost reports whether a URL's host (with any port) and hostname are an IP literal or an ASCII
// host name.
func isHost(host, hostname string) bool {
	if hostname == "" || strings.ContainsAny(host, "%") {
		return false
	}

	if _, err := netip.ParseAddr(hostname); err == nil {
		return true
	}

	return isHostName(hostname)
}

// isHostName reports whether name is dot-separated labels of ASCII letters, digits, hyphens and
// underscores, as in a DNS name. The last label can't be all digits (RFC 3696 §2): browsers read
// names such as 0.0 or 127.1 as IPv4 addresses.
func isHostName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}

	if last := name[strings.LastIndex(name, ".")+1:]; isDigits(last) {
		return false
	}

	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}

		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}

	return true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}
