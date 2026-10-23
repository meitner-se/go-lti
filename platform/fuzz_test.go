package platform

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/ltitest"
)

func FuzzParseRegistration(f *testing.F) {
	vectors := loadVectors[registrationVector](f, "registration")
	for name := range vectors {
		f.Add([]byte(vectors[name].Request))
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

		// Checked by hand rather than with the package's own helpers.
		tool := reg.Tool("client")
		for _, domain := range tool.Domains {
			if domain == "" || strings.ContainsAny(domain, ":/?#@* ") {
				t.Fatalf("accepted domain %q", domain)
			}
		}

		for _, uri := range append([]string{tool.InitiateLoginURI, tool.TargetLinkURI, tool.JWKSURI}, tool.RedirectURIs...) {
			if !strings.HasPrefix(uri, "https://") {
				t.Fatalf("accepted a non-https uri %q", uri)
			}
		}

		for _, uri := range tool.RedirectURIs {
			if strings.Contains(uri, "#") {
				t.Fatalf("accepted a redirect uri with a fragment %q", uri)
			}
		}

		if !slices.Contains(reg.GrantTypes, "implicit") || !slices.Contains(reg.ResponseTypes, "id_token") || reg.TokenEndpointAuthMethod != "private_key_jwt" {
			t.Fatalf("accepted a registration without what LTI requires: %+v", reg)
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

// FuzzVerify signs fuzzed response claims with a real tool key and checks every accepted response
// against the rules Verify promises, worked out from the claims rather than from Verify's code.
func FuzzVerify(f *testing.F) {
	f.Add(int64(0), int64(300), "nonce", "request-1", "deployment-1", "https://platform.example.com/lti", "client-1")
	f.Add(int64(30), int64(3630), "n", "request-1", "deployment-1", "https://platform.example.com/lti", "client-1")
	f.Add(int64(-7200), int64(-30), "n", "", "deployment-1", "https://platform.example.com/lti", "client-1")
	f.Add(int64(0), int64(300), "", "x", "", "", "")

	tool := ltitest.NewSigningKey(f)
	toolKey := ltitest.PublicKey(f, tool)
	now := testNow
	keys := &mockKeySource{KeyFunc: func(context.Context, string, string) (*rsa.PublicKey, error) { return toolKey.PublicKey, nil }}

	f.Fuzz(func(t *testing.T, iatOffset, expOffset int64, nonce, data, deployment, audience, issuer string) {
		verifier, err := NewDeepLinkingVerifier(createTestConfig(), keys, ltitest.NewNonceStore(t), WithClock(func() time.Time { return now }))
		require.NoError(t, err)

		claims := createTestDeepLinkingResponseClaims(now)
		claims["iat"] = now.Unix() + iatOffset%100000
		claims["exp"] = now.Unix() + expOffset%100000
		claims["nonce"] = nonce
		claims[lti.ClaimDeepLinkingData] = data
		claims[lti.ClaimDeploymentID] = deployment
		claims["aud"] = audience
		claims["iss"] = issuer

		_, err = verifier.Verify(t.Context(), ltitest.Sign(t, tool, claims), createTestDeepLinkingSession())
		if err != nil {
			if _, ok := lti.AsError(err); !ok {
				t.Fatalf("Verify returned a non-lti error: %v", err)
			}

			return
		}

		iat, exp := iatOffset%100000, expOffset%100000

		switch {
		case issuer != "client-1" || audience != "https://platform.example.com/lti":
			t.Fatalf("accepted iss %q and aud %q", issuer, audience)
		case deployment != "deployment-1":
			t.Fatalf("accepted deployment %q", deployment)
		case data != "request-1":
			t.Fatalf("accepted data %q", data)
		case nonce == "" || len(nonce) > 1024:
			t.Fatalf("accepted nonce %q", nonce)
		case exp < iat || exp-iat > 3600:
			t.Fatalf("accepted a lifetime of %d s", exp-iat)
		case exp < -60 || iat > 60:
			t.Fatalf("accepted iat %+d s and exp %+d s from now", iat, exp)
		}
	})
}

func FuzzParseAuthenticationRequest(f *testing.F) {
	for _, v := range loadVectors[authenticationRequestVector](f, "authentication_request") {
		f.Add(v.Form.Encode())
	}

	f.Add("client_id=&redirect_uri=&nonce=")
	f.Add("scope=openid%20openid&response_type=id_token&response_type=id_token")

	f.Fuzz(func(t *testing.T, query string) {
		form, err := url.ParseQuery(query)
		if err != nil {
			return
		}

		req, err := ParseAuthenticationRequest(form)
		if req == nil {
			t.Fatal("ParseAuthenticationRequest returned no request")
		}

		if err != nil {
			if _, ok := lti.AsError(err); !ok {
				t.Fatalf("ParseAuthenticationRequest returned a non-lti error: %v", err)
			}

			return
		}

		for name, value := range map[string]string{"client_id": req.ClientID, "redirect_uri": req.RedirectURI, "login_hint": req.LoginHint, "nonce": req.Nonce} {
			if value == "" || len(value) > maxAuthenticationParameterBytes {
				t.Fatalf("accepted %s %q", name, value)
			}
		}

		for name, values := range form {
			if len(values) != 1 {
				t.Fatalf("accepted repeated %s", name)
			}
		}

		openid := false
		for _, scope := range strings.Fields(form.Get("scope")) {
			openid = openid || scope == "openid"
		}

		if !openid || form.Get("response_type") != "id_token" || form.Get("response_mode") != "form_post" || form.Get("prompt") != "none" {
			t.Fatalf("accepted a request that isn't an LTI authentication request: %v", form)
		}
	})
}
