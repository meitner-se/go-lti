# go-lti

LTI 1.3 and LTI Advantage for Go, for the platform side: the system that launches tools, such as an LMS.

It covers the launch (the OIDC third-party login flow and the signed id_token), verifying Deep Linking 2.0 responses, Dynamic Registration 1.0, and the platform's OpenID configuration and JWKS. LTI 1.1 is not supported.

```sh
go get github.com/meitner-se/go-lti
```

Work in progress: the API may change until v1.0.0.

## Packages

| Package | What it does |
| -- | -- |
| `lti` | Types both sides of LTI share: messages and claims, content items, roles, scopes and other spec vocabulary, signing keys, and `Error`. |
| `platform` | The platform side: its `Config`, its record of each `Tool`, the launch flow, Deep Linking verification, Dynamic Registration and the OpenID configuration. |
| `jwks` | Publishes the platform's keys and fetches tools' keys, with caching. |
| `safehttp` | An HTTP client that won't connect to private or internal addresses, for URLs a tool controls. |
| `ltitest` | Test keys, a JWKS server and an in-memory nonce store. |

go-lti does no I/O except fetching a tool's keys. It has no routes, storage or cookies: you pass plain values and implement three small interfaces, `lti.Keys` (your signing key), `lti.KeySource` (tools' keys; `jwks.Fetcher` implements it) and `lti.NonceStore` (replay protection, shared by your replicas).

Where the spec leaves a choice to the platform, such as what a user's `sub` is or which roles they have, go-lti takes your value and doesn't make the choice for you.

## Quickstart

Describe your platform once:

```go
cfg := platform.Config{
	Issuer:        "https://lms.example.com/lti",
	Paths:         platform.Paths{Authorization: "/authorize", JWKS: "/jwks", Registration: "/register", DeepLinkReturn: "/deep-link-return"},
	TokenEndpoint: "https://lms.example.com/oauth/token",
	Product: platform.Product{GUID: "lms-1", Name: "Example LMS", FamilyCode: "example-lms", Version: "1.0.0"},
	// The substitution variables a launch fills in, plus any you supply in lti.Common.Variables.
	Variables: platform.LaunchVariables(),
}
```

Launch a tool. The hints are opaque to go-lti: your platform decides what they are and redeems them.

```go
keys, err := lti.StaticKeys(lti.SigningKey{Signer: privateKey}) // kid defaults to the key's thumbprint

// 1. Where the user clicks: redirect the browser to the tool.
initiation := platform.LoginInitiation{DeploymentID: deploymentID, LoginHint: userHint, MessageHint: launchHint}
loginURL, err := cfg.LoginInitiationURL(tool, initiation)

// 2. The tool's authentication request comes back to Paths.Authorization. NewHandler parses it,
// calls your Launch, signs the id_token and posts it to the tool, or sends it the error. It also
// serves your public keys at Paths.JWKS.
handler, err := platform.NewHandler(cfg, platform.Handlers{
	Register: register,
	Keys:     keys,
	Launch: func(r *http.Request, req *platform.AuthenticationRequest) (*platform.Launch, error) {
		// Redeem req.MessageHint, and check that a session in r belongs to the launch's user.
		return &platform.Launch{
			Tool:       tool,
			Initiation: initiation,
			Message: &lti.ResourceLinkRequest{
				Common: lti.Common{
					DeploymentID: deploymentID,
					Subject:      sub,
					Roles:        []lti.Role{lti.RoleLearner},
					Custom:       linkCustomParameters, // as configured, such as {"course": "$Context.id"}
				},
				ResourceLink: lti.ResourceLink{ID: linkID},
			},
		}, nil
	},
})
```

A platform with its own HTTP handling can call `platform.ParseAuthenticationRequest`, `platform.NewLauncher(cfg, keys)`, `launcher.Respond`, `launcher.RespondError` and `launcher.JWKS` itself.

Pass custom parameters as configured: the launch substitutes their variables (LTI 1.3 Appendix B) from the message itself, such as `$Context.id` from `Context` and `$Person.name.full` from `User`, so a custom parameter always agrees with the claim next to it. Supply variables the message doesn't carry, such as `$User.username`, in `Common.Variables`. A variable from `platform.LaunchVariables()` without a value in either place is sent as an empty string, as Appendix B asks of a supported variable; any other variable without a value stays as it is, which tells the tool the platform doesn't support it. Variables about the user are only filled in when `Sharing` allows, and are sent as an empty string when it doesn't, even when you supply them.

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
	http.Error(w, rejection.Description, rejection.StatusCode()) // the tool's mistake
	return
}
if err != nil {
	http.Error(w, "the response could not be checked", http.StatusBadGateway) // a jwks or nonce store failure
	return
}
```

Load the session from your own state for this browser, such as the record behind the session cookie, never from the posted JWT. `nonces` must be shared by every replica and keep each nonce until the time `Claim` is given.

Handle a Dynamic Registration:

```go
// Send the admin's browser to the tool's registration URL.
startURL, err := cfg.RegistrationInitiationURL(toolRegistrationURL, cfg.Endpoints().OpenIDConfiguration, registrationToken)

// Serve the OpenID configuration and the registration endpoint. Your Register checks the token,
// saves the tool and returns what it granted; the handler answers the tool per the spec.
handler, err := platform.NewHandler(cfg, platform.Handlers{Register: register})
http.Handle("/lti/", handler) // everything under the issuer's path, with the path unchanged

// In Register, before activating the tool:
review := reg.Review(cfg) // show this to an admin
tool := reg.Tool(clientID)
```

The platform's endpoints are the issuer plus `cfg.Paths`, listed by `cfg.Endpoints()`. Only the OpenID configuration's path is set by a spec (`platform.PathOpenIDConfiguration`); you choose the others, and tools learn them from the OpenID configuration, the registration response or a launch. Once a tool has registered it keeps the URLs it was given, so don't change a path after that. The package examples on [pkg.go.dev](https://pkg.go.dev/github.com/meitner-se/go-lti) run as tests.

## Errors

A rejection of something a tool or a browser sent is an `*lti.Error` with the spec's error code (such as `invalid_request` or `invalid_redirect_uri`) and a description that is safe to send back. Any other error is your platform's own, such as a signer or network failure.

## Test vectors

`testdata/vectors/` holds JSON cases with their expected results, for JWKS documents, Dynamic Registration requests and Deep Linking responses. go-lti's tests run them, and an implementation in another language can run the same cases. See [testdata/vectors/README.md](testdata/vectors/README.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

MIT
