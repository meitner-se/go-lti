package platform

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
)

func FuzzParseRegistration(f *testing.F) {
	for _, v := range loadVectors[registrationVector](f, "registration") {
		f.Add([]byte(v.Request))
	}

	f.Add([]byte(`{"client_name#":"x"}`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, body []byte) {
		reg, err := ParseRegistration(body)
		if err != nil {
			if _, ok := lti.AsError(err); !ok {
				t.Fatalf("ParseRegistration returned a non-lti error: %v", err)
			}

			return
		}

		tool := reg.Tool("client")
		for _, domain := range tool.Domains {
			if !urlcheck.IsDomain(domain) {
				t.Fatalf("accepted domain %q", domain)
			}
		}

		for _, uri := range append([]string{tool.InitiateLoginURI, tool.TargetLinkURI}, tool.RedirectURIs...) {
			if !urlcheck.OnDomains(uri, tool.Domains) {
				t.Fatalf("accepted %q off the tool's domains %v", uri, tool.Domains)
			}
		}

		if !urlcheck.IsHTTPS(tool.JWKSURI) {
			t.Fatalf("accepted jwks_uri %q", tool.JWKSURI)
		}
	})
}

func FuzzContentItems(f *testing.F) {
	for _, v := range loadVectors[deepLinkingVector](f, "deep_linking") {
		if items, ok := v.Claims[lti.ClaimContentItems]; ok {
			body, err := json.Marshal(items)
			if err != nil {
				f.Fatal(err)
			}

			f.Add(body)
		}
	}

	f.Add([]byte(`[{"type":"ltiResourceLink","url":"https://tool.example.com/a"}]`))
	f.Add([]byte(`[{"type":"link"},{"type":"html","html":""}]`))

	domains := []string{"tool.example.com"}
	settings := lti.DeepLinkingSettings{AcceptTypes: allContentItemTypes, AcceptMultiple: true}

	f.Fuzz(func(t *testing.T, body []byte) {
		var raw []json.RawMessage
		if json.Unmarshal(body, &raw) != nil {
			return
		}

		items, err := parseContentItems(raw, domains, settings)
		if err != nil {
			if _, ok := lti.AsError(err); !ok {
				t.Fatalf("parseContentItems returned a non-lti error: %v", err)
			}

			return
		}

		for i := range items {
			if !slices.Contains(settings.AcceptTypes, items[i].Type) {
				t.Fatalf("accepted type %q", items[i].Type)
			}

			for _, u := range itemURLs(items[i]) {
				if !urlcheck.OnDomains(u, domains) {
					t.Fatalf("accepted url %q off the tool's domains", u)
				}
			}
		}
	})
}
