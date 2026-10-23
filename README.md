# go-lti

LTI 1.3 and LTI Advantage for Go, for the platform side: the system that launches tools, such as an LMS.

It covers signing the id_token a tool is launched with, verifying Deep Linking 2.0 responses, Dynamic Registration 1.0, and the platform's OpenID configuration and JWKS. LTI 1.1 is not supported.

```sh
go get github.com/meitner-se/go-lti
```

Work in progress: the API may change until v1.0.0.

## Packages

| Package | What it does |
| -- | -- |
| `lti` | Types both sides of LTI share: messages and claims, content items, roles, scopes and other spec vocabulary, signing keys, and `Error`. |
| `platform` | The platform side: its `Config`, its record of each `Tool`, id_tokens, Deep Linking verification, Dynamic Registration and the OpenID configuration. |
| `jwks` | Publishes the platform's keys and fetches tools' keys, with caching. |
| `safehttp` | An HTTP client that won't connect to private or internal addresses, for URLs a tool controls. |
| `ltitest` | Test keys, a JWKS server and an in-memory nonce store. |

go-lti does no I/O except fetching a tool's keys. It has no routes, storage or cookies: you pass plain values and implement three small interfaces, `lti.Keys` (your signing key), `lti.KeySource` (tools' keys; `jwks.Fetcher` implements it) and `lti.NonceStore` (replay protection, shared by your replicas).

Where the spec leaves a choice to the platform, such as what a user's `sub` is or which roles they have, go-lti takes your value and doesn't make the choice for you.

## Quickstart

Describe your platform once:

```go
cfg := platform.Config{
	Issuer: "https://lms.example.com/lti",
	Endpoints: platform.Endpoints{
		Authorization:  "https://lms.example.com/lti/authorize",
		JWKS:           "https://lms.example.com/lti/jwks",
		Registration:   "https://lms.example.com/lti/register",
		Token:          "https://lms.example.com/oauth/token",
		DeepLinkReturn: "https://lms.example.com/lti/deep-link-return",
	},
	Product: platform.Product{GUID: "lms-1", Name: "Example LMS", FamilyCode: "example-lms", Version: "1.0.0"},
}
```

Verify a tool's Deep Linking response:

```go
fetcher, err := jwks.NewFetcher()
verifier, err := platform.NewDeepLinkingVerifier(cfg, fetcher, nonces)

response, err := verifier.Verify(ctx, r.PostFormValue(lti.DeepLinkingResponseField), platform.DeepLinkingSession{
	Tool:         tool,
	DeploymentID: deploymentID,
	Settings:     settingsYouSent,
})
if rejection, ok := lti.AsError(err); ok {
	http.Error(w, rejection.Description, rejection.StatusCode())
	return
}
```

Handle a Dynamic Registration:

```go
reg, err := platform.ParseRegistration(body)
review := reg.Review(cfg) // show this to an admin before activating the tool
tool := reg.Tool(clientID)
response := reg.Response(platform.RegistrationGrant{ClientID: clientID, DeploymentID: deploymentID})
```

Serve `cfg.OpenIDConfiguration()` at the URL you hand tools for Dynamic Registration. The package examples on [pkg.go.dev](https://pkg.go.dev/github.com/meitner-se/go-lti) run as tests.

## Errors

A rejection of something a tool or a browser sent is an `*lti.Error` with the spec's error code (such as `invalid_request` or `invalid_redirect_uri`) and a description that is safe to send back. Any other error is your platform's own, such as a signer or network failure.

## Test vectors

`testdata/vectors/` holds JSON cases with their expected results, for JWKS documents, Dynamic Registration requests and Deep Linking responses. go-lti's tests run them, and an implementation in another language can run the same cases. See [testdata/vectors/README.md](testdata/vectors/README.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

MIT
