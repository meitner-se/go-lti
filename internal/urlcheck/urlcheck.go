// Package urlcheck holds the URL and domain checks that several go-lti packages share.
package urlcheck

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ParseHTTPS parses raw and reports whether it is an absolute https URL without credentials.
func ParseHTTPS(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
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
// one. Domains that are public suffixes never match.
func OnDomains(raw string, domains []string) bool {
	u, ok := ParseHTTPS(raw)
	if !ok {
		return false
	}

	host := NormalizeDomain(u.Hostname())
	for _, domain := range domains {
		domain = NormalizeDomain(domain)
		if domain == "" || IsPublicSuffix(domain) {
			continue
		}

		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

// NormalizeDomain lowercases a domain and drops a port and a trailing dot.
func NormalizeDomain(domain string) string {
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}

	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// IsDomain reports whether domain is a bare host name that isn't a public suffix, so that matching
// subdomains of it can't cover other sites, such as everything under co.uk or github.io.
func IsDomain(domain string) bool {
	if domain == "" || strings.ContainsAny(domain, "/?#@ ") {
		return false
	}

	u, err := url.Parse("https://" + domain)
	if err != nil || u.Host != domain || u.Hostname() == "" {
		return false
	}

	return !IsPublicSuffix(u.Hostname())
}

// IsPublicSuffix reports whether domain is a suffix under which unrelated parties register names,
// from both the ICANN and the private sections of the Public Suffix List. A domain the list
// doesn't know, such as a bare "localhost", counts as one.
func IsPublicSuffix(domain string) bool {
	domain = NormalizeDomain(domain)
	suffix, _ := publicsuffix.PublicSuffix(domain)

	return suffix == domain
}
