package platform

import (
	"encoding/json"
	"slices"
	"strings"
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
	vectors := loadVectors[deepLinkingVector](f, "deep_linking")
	for name := range vectors {
		if items, ok := vectors[name].Claims[lti.ClaimContentItems]; ok {
			body, err := json.Marshal(items)
			if err != nil {
				f.Fatal(err)
			}

			f.Add(body)
		}
	}

	f.Add([]byte(`[{"type":"ltiResourceLink","url":"https://tool.example.com/a"}]`))
	f.Add([]byte(`[{"type":"link"},{"type":"html","html":""}]`))
	f.Add([]byte(`[{"type":"link","url":"https://evil.example/","URL":"https://tool.example.com/"}]`))
	f.Add([]byte(`[{"type":"link","url":"https://a.example/","iframe":{"width":1.5}}]`))

	settings := lti.DeepLinkingSettings{AcceptTypes: allContentItemTypes, AcceptMultiple: true}

	f.Fuzz(func(t *testing.T, body []byte) {
		var raw []json.RawMessage
		if json.Unmarshal(body, &raw) != nil {
			return
		}

		items, err := parseContentItems(raw, settings)
		if err != nil {
			if _, ok := lti.AsError(err); !ok {
				t.Fatalf("parseContentItems returned a non-lti error: %v", err)
			}

			return
		}

		// Check each accepted item against its raw JSON, read independently with exact keys.
		for i := range items {
			var exact map[string]any
			if err := json.Unmarshal(raw[i], &exact); err != nil {
				t.Fatalf("accepted an item that isn't an object: %s", raw[i])
			}

			itemType, _ := exact["type"].(string)
			if !slices.Contains(settings.AcceptTypes, lti.ContentItemType(itemType)) || itemType != string(items[i].Type) {
				t.Fatalf("accepted type %q, raw type %q", items[i].Type, itemType)
			}

			if rawURL, ok := exact["url"].(string); ok && rawURL != items[i].URL {
				t.Fatalf("validated url %q but raw url %q", items[i].URL, rawURL)
			}

			for _, u := range rawURLs(exact) {
				if !strings.HasPrefix(u, "https://") {
					t.Fatalf("accepted a non-https url %q", u)
				}
			}
		}
	})
}

// rawURLs returns the url, icon.url, thumbnail.url and iframe.src members of a raw item.
func rawURLs(item map[string]any) []string {
	var urls []string

	if u, ok := item["url"].(string); ok && u != "" {
		urls = append(urls, u)
	}

	for _, member := range []string{"icon", "thumbnail"} {
		if image, ok := item[member].(map[string]any); ok {
			u, _ := image["url"].(string)
			urls = append(urls, u)
		}
	}

	if iframe, ok := item["iframe"].(map[string]any); ok {
		if u, ok := iframe["src"].(string); ok && u != "" {
			urls = append(urls, u)
		}
	}

	return urls
}
