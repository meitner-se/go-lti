package urlcheck

import (
	"strings"
	"testing"
)

// FuzzOnDomains checks OnDomains against rules derived independently of it: a match needs an https
// URL whose lowercased ASCII host equals the domain or ends with "." and the domain, for a domain
// with at least two labels.
func FuzzOnDomains(f *testing.F) {
	f.Add("https://tool.example.com/a", "tool.example.com")
	f.Add("https://sub.tool.example.com:8443/a?b#c", "Tool.Example.com.")
	f.Add("https://evil.com／.tool.example.com/", "tool.example.com")
	f.Add("https://eviltool.example.com/", "tool.example.com")
	f.Add("http://tool.example.com/", "tool.example.com")
	f.Add("https://someone.github.io/", "github.io")

	f.Fuzz(func(t *testing.T, raw, domain string) {
		if !OnDomains(raw, []string{domain}) {
			return
		}

		// Schemes are case-insensitive (RFC 3986 §3.1).
		if len(raw) < len("https://") || !strings.EqualFold(raw[:len("https://")], "https://") {
			t.Fatalf("matched a non-https url %q", raw)
		}

		rest := raw[len("https://"):]

		host := rest
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}

		if strings.Contains(host, "@") {
			t.Fatalf("matched a url with credentials %q", raw)
		}

		if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host, "]") {
			host = host[:i]
		}

		host = strings.TrimSuffix(strings.ToLower(host), ".")
		want := strings.ToLower(strings.TrimSpace(domain))
		if j := strings.LastIndex(want, ":"); j >= 0 {
			want = want[:j]
		}

		want = strings.TrimSuffix(want, ".")

		for _, r := range host {
			if r > 0x7f {
				t.Fatalf("matched a non-ascii host %q", host)
			}
		}

		if !strings.Contains(want, ".") {
			t.Fatalf("matched single-label domain %q", domain)
		}

		if host != want && !strings.HasSuffix(host, "."+want) {
			t.Fatalf("host %q is not %q or under it", host, want)
		}
	})
}
