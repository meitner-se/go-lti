package urlcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Tests
// ============================================================================

func TestParseHTTPS(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"https://tool.example.com/launch":             true,
		"https://tool.example.com:8443/launch":        true,
		"https://TOOL.example.com./launch":            true,
		"https://93.184.215.14/x":                     true,
		"https://[2606:2800:21f:cb07::1]/x":           true,
		"https://xn--bcher-kva.example/x":             true,
		"http://tool.example.com/launch":              false,
		"https:///launch":                             false,
		"https://user:pass@tool.example.com/":         false,
		"https://evil.com／.tool.example.com/":         false,
		"https://evil.com%EF%BC%8F.tool.example.com/": false,
		"https://evil.com＠.tool.example.com/":         false,
		"https://bücher.example/":                     false,
		"https://*.example.com/":                      false,
		"https://tool..example.com/":                  false,
		"https://0.0/x":                               false,
		"https://127.1/x":                             false,
		"https://[fe80::1%25en0]/x":                   false,
		"javascript:alert(1)":                         false,
		"/relative":                                   false,
		"":                                            false,
	}

	for raw, want := range tests {
		_, got := ParseHTTPS(raw)
		assert.Equal(t, want, got, raw)
	}
}

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"Tool.Example.COM":         "tool.example.com",
		"\ttool.example.com\n":     "tool.example.com",
		"tool.example.com.":        "tool.example.com",
		"tool.example.com:8443":    "tool.example.com",
		"https://cdn.example.com":  "https://cdn.example.com",
		"cdn.example.com:evil.org": "cdn.example.com:evil.org",
		"cdn.example.com:":         "cdn.example.com:",
	}

	for in, want := range tests {
		assert.Equal(t, want, NormalizeDomain(in), in)
	}
}

func TestIsDomain(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"tool.example.com":          true,
		"example.com":               true,
		"sub_domain.example.com":    true,
		"xn--bcher-kva.example.com": true,
		"com":                       false,
		"co.uk":                     false,
		"github.io":                 false,
		"localhost":                 false,
		"":                          false,
		"https://tool.example.com":  false,
		"tool.example.com/lti":      false,
		"tool.example.com:8443":     false,
		"user@tool.example.com":     false,
		"*.example.com":             false,
		"evil.com／x.com":            false,
		"tool.example.com.":         false,
		"tool..example.com":         false,
		"1.2.3.4":                   false,
		"2001:db8::1":               false,
	}

	for domain, want := range tests {
		assert.Equal(t, want, IsDomain(domain), domain)
	}
}

func TestOnDomains(t *testing.T) {
	t.Parallel()

	domains := []string{"tool.example.com", "CDN.example.net", "github.io", "", "https://bad.example.org"}

	tests := map[string]bool{
		"https://tool.example.com/a":          true,
		"https://sub.tool.example.com/a":      true,
		"https://TOOL.example.com./a":         true,
		"https://tool.example.com:8443/a":     true,
		"https://cdn.example.net/a.png":       true,
		"https://eviltool.example.com/a":      false,
		"https://tool.example.com.evil.org/a": false,
		"http://tool.example.com/a":           false,
		"https://someone.github.io/a":         false,
		"https://bad.example.org/a":           false,
		"https://evil.com／.tool.example.com/": false,
		"https://user@tool.example.com/":      false,
	}

	for raw, want := range tests {
		assert.Equal(t, want, OnDomains(raw, domains), raw)
	}
}

func TestIsPublicSuffix(t *testing.T) {
	t.Parallel()

	for domain, want := range map[string]bool{"com": true, "co.uk": true, "github.io": true, "localhost": true, "example.com": false, "a.github.io": false} {
		assert.Equal(t, want, IsPublicSuffix(domain), domain)
	}
}
