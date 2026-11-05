# go-lti

LTI 1.3 and LTI Advantage for Go, for the platform side: the system that launches tools, such as an LMS.

It covers the launch (the OIDC third-party login flow and the signed id_token), verifying Deep Linking 2.0 responses, Dynamic Registration 1.0, the platform's OpenID configuration and JWKS, Names and Role Provisioning Services 2.0 (the launch claim and the memberships endpoint) and Assignment and Grade Services 2.0 (the launch claim and the line item, score and result endpoints). LTI 1.1 is not supported.

```sh
go get github.com/meitner-se/go-lti
```

Work in progress: the API may change until v1.0.0.

## Packages

| Package | What it does |
| -- | -- |
| `lti` | Types both sides of LTI share: messages and claims, content items, membership containers, line items, scores and results, roles, scopes and other spec vocabulary, signing keys, and `Error`. |
| `platform` | The platform side: its `Config`, its record of each `Tool`, the launch flow, Deep Linking verification, Dynamic Registration, the OpenID configuration, the Names and Role Provisioning Services endpoint and the Assignment and Grade Services endpoints. |
| `jwks` | Publishes the platform's keys and fetches tools' keys, with caching. |
| `safehttp` | An HTTP client that won't connect to private or internal addresses, for URLs a tool controls. |
| `ltitest` | Test keys, a JWKS server and an in-memory nonce store. |

go-lti does no I/O except fetching a tool's keys. It has no routes, storage or cookies: you pass plain values and implement three small interfaces, `lti.Keys` (your signing key), `lti.KeySource` (tools' keys; `jwks.Fetcher` implements it) and `lti.NonceStore` (replay protection, shared by your replicas).

For the simple cases there are ready-made ones: `lti.ParseKeysPEM` loads your current signing key and the next one from PEM, `lti.NewDevelopmentKeys` generates a key for local development, and `lti.MemoryNonceStore` remembers nonces in one process. `lti.ParseContentItemType` and `lti.ParseDocumentTarget` read vocabulary you stored as strings back, refusing unknown values.

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
keys, err := lti.ParseKeysPEM(currentKeyPEM, nextKeyPEM) // nextKeyPEM may be empty; each kid is the key's thumbprint

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

Receive a tool's Deep Linking response at `Paths.DeepLinkReturn` (Deep Linking 2.0 §4.2). `NewHandler` serves it when you set its four Deep Linking fields: it reads the posted JWT, calls `FindDeepLinkingSession` with the response's unverified `iss`, `aud`, `deployment_id` and `data`, verifies the response against the session you return, and hands you the outcome:

```go
fetcher, err := jwks.NewFetcher()

handler, err := platform.NewHandler(cfg, platform.Handlers{
	Register: register,
	ToolKeys: fetcher,
	Nonces:   nonces,
	FindDeepLinkingSession: func(r *http.Request, unverified platform.UnverifiedDeepLinkingResponse) (platform.DeepLinkingSession, error) {
		// Look the request up in your own state: by unverified.Data, the browser's session in r, or
		// both. data is optional in the spec, so don't rely on it alone.
		return platform.DeepLinkingSession{Tool: tool, DeploymentID: deploymentID, Settings: settingsYouSent}, nil
		// or platform.ErrDeepLinkingSessionNotFound for a request that is unknown, expired or answered
	},
	HandleDeepLinkingResponse: func(w http.ResponseWriter, r *http.Request, result platform.DeepLinkingResult) {
		if rejection, ok := lti.AsError(result.Err); ok {
			// The tool's mistake: record rejection.Description for the user.
		} else if result.Err != nil {
			// A jwks or nonce store failure: ask the user to try again.
		} else {
			// Save result.Response.Items, after any checks of your own, such as platform.OnToolDomains.
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, whereTheUserStarted, http.StatusSeeOther)
	},
})
```

The claims `FindDeepLinkingSession` gets are read before the signature is checked, so they only serve as a key: the session you return comes from your own state, and the response is verified against it. A response with no session gets a plain error page: 413 for a body over the form limit; 400 for `ErrDeepLinkingSessionNotFound`, a missing JWT, one over `MaxDeepLinkingResponseBytes` or one without any of the lookup claims; another `*lti.Error` from the lookup gets its own status; and a `server_error` or any other lookup error gets a 500 that says nothing more. `HandleDeepLinkingResponse` gets the session even when verification fails, so you can send the user back to where they started with the error.

`nonces` must be shared by every replica and keep each nonce until the time `Claim` is given. `lti.MemoryNonceStore` only covers one process: use it with a single replica, or when your platform accepts one response per request anyway.

A platform with its own HTTP handling can call `platform.ParseUnverifiedDeepLinkingResponse` and `platform.NewDeepLinkingVerifier(cfg, fetcher, nonces).Verify` itself.

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

## Names and Role Provisioning Services

Names and Role Provisioning Services 2.0 lets a tool read who is in a context, such as a course's teachers and students. Set `Paths.ContextMemberships` to a prefix, and a context's members are at the issuer plus the prefix plus `/{context}/memberships`. Send the tool that URL with the launch, built by `cfg.ContextMembershipsURL`, which path-escapes the context's id, and the launch carries the `namesroleservice` claim with service version 2.0:

```go
cfg.Paths.ContextMemberships = "/contexts" // https://lms.example.com/lti/contexts/{context}/memberships

membershipsURL, err := cfg.ContextMembershipsURL(contextID)

Common: lti.Common{
	// ...
	Context:               &lti.LaunchContext{ID: contextID},
	ContextMembershipsURL: membershipsURL,
},
```

The claim belongs to the launch's context, so a launch with a `ContextMembershipsURL` needs a `Context`. Without the URL there is no claim. Send it only to a tool your platform lets read the context's members, such as one granted the `lti.ScopeNRPSMembershipRead` scope.

`NewHandler` serves the endpoint when you set `Paths.ContextMemberships` and `ListContextMembers` together, with `AuthorizeService`, which every LTI service endpoint shares. The access token and the members are yours, so it asks you for them:

```go
handler, err := platform.NewHandler(cfg, platform.Handlers{
	Register: register,
	// Shared by every LTI service endpoint; scope is the one the endpoint needs.
	AuthorizeService: func(r *http.Request, token string, scope lti.Scope) (platform.ServiceClient, error) {
		// Look the token up where your token endpoint issued it.
		return platform.ServiceClient{ClientID: clientID, Scopes: grantedScopes}, nil
		// or an *lti.Error with lti.ErrorInvalidToken (401) or lti.ErrorInsufficientScope (403)
	},
	ListContextMembers: func(r *http.Request, client platform.ServiceClient, req platform.MembershipsRequest) (platform.MembershipsPage, error) {
		// Check that client may read req.ContextID, then read a page of its members, filtered by
		// req.Role and req.ResourceLinkID, at most req.Limit of them (0 for your own page size),
		// starting at req.PageToken.
		return platform.MembershipsPage{
			Context:       lti.MembershipContext{ID: req.ContextID},
			Members:       []lti.Member{{Status: lti.MembershipStatusActive, UserID: sub, Roles: []lti.Role{lti.RoleLearner}}},
			NextPageToken: nextPageToken, // "" on the last page
		}, nil
		// or platform.ErrContextNotFound (404) for a context that doesn't exist or client may not read
	},
})
```

The handler reads the request's Bearer token (RFC 6750) and answers a request without one with 401 and `WWW-Authenticate: Bearer`, before calling `AuthorizeService`. A token you refuse gets RFC 6750's challenge with its error code, and so does a client whose `Scopes` don't include the endpoint's scope (403 `insufficient_scope`): the handler checks the scope, so `AuthorizeService` only has to validate the token. `AuthorizeService` without a service that uses it is a configuration error. `ErrContextNotFound` is answered 404 with the same JSON error body as the other errors. It answers a page as an `lti.MembershipContainer` with the media type `lti.MembershipContainerMediaType` and `Cache-Control: no-store`. The container's `id` is the request's URL, and while there is a next page it is linked as `rel="next"`: the same URL with your `NextPageToken`, keeping the tool's `role`, `limit` and `rlid`. The page token is opaque to go-lti and the tool.

A member's `UserID` is the `sub` the same tool gets in launches. Fill in the name, email and other personal data only when the tool may have it, as `Sharing` decides in a launch; empty fields are left out.

A platform with its own HTTP handling can answer with an `lti.MembershipContainer` itself, and link the next page (`rel="next"`) and, if it offers one, the changes since (`rel="differences"`) with `platform.AddMembershipLinks`.

## Assignment and Grade Services

Assignment and Grade Services 2.0 lets a tool send scores back to the platform's gradebook. Each gradebook column is a line item; a tool posts a user's score to it and reads the platform's results. Tell the tool where with the launch's `AGSEndpoint`, and the launch carries the `endpoint` claim:

```go
cfg.Paths.ContextLineItems = "/contexts" // https://lms.example.com/lti/contexts/{context}/lineitems

lineItemsURL, err := cfg.LineItemsURL(contextID)
lineItemURL, err := cfg.LineItemURL(contextID, lineItemID) // the link's only line item, if it has one

Common: lti.Common{
	// ...
	Context: &lti.LaunchContext{ID: contextID},
	AGSEndpoint: &lti.AGSEndpoint{
		Scopes:    []lti.Scope{lti.ScopeAGSLineItem, lti.ScopeAGSResultReadOnly, lti.ScopeAGSScore},
		LineItems: lineItemsURL,
		LineItem:  lineItemURL,
	},
},
```

The line item container belongs to the launch's context, so a launch with an `AGSEndpoint` needs a `Context`. It needs at least one scope, only the four `lti.ScopeAGS*` scopes, and a `LineItems` or `LineItem` URL, each absolute https. Leave `LineItems` empty for a tool that may only post scores, and `LineItem` empty when the link has no line item or several; a Deep Linking request can't have a `LineItem`. Without an `AGSEndpoint` there is no claim. List only scopes your platform grants the tool.

The service's bodies are `lti.LineItem` (and `lti.LineItemContainer`, a list of them), `lti.Score` and `lti.ResultContainer` of `lti.Result`, with the media types `lti.LineItemContainerMediaType`, `lti.LineItemMediaType`, `lti.ScoreMediaType` and `lti.ResultContainerMediaType`. Empty optional fields are left out, and an empty container is sent as `[]`. A score's `ScoreGiven` is a pointer, since 0 is a score and nil is none; its `ActivityProgress` and `GradingProgress` are the spec's values, such as `lti.ActivityProgressCompleted` and `lti.GradingProgressFullyGraded`. Times are written in ISO 8601 to the millisecond or finer, and read in every form the spec allows, including an offset such as `+00`, and ISO 8601's basic offset such as `+0000`; a blank or null line item time is nil.

`NewHandler` serves the line item, score and result endpoints when you set `Paths.ContextLineItems` and all seven line item hooks together, with `AuthorizeService`. `Paths.ContextLineItems` may be the same prefix as `Paths.ContextMemberships`. Under `{prefix}/{context}/lineitems` it serves:

| Route | Scope | Hook | Answer |
| -- | -- | -- | -- |
| `GET` | `lineitem` or `lineitem.readonly` | `ListLineItems` | 200, `lti.LineItemContainerMediaType` |
| `POST` | `lineitem` | `CreateLineItem` | 201, `lti.LineItemMediaType`, `Location` |
| `GET /{lineitem}` | `lineitem` or `lineitem.readonly` | `GetLineItem` | 200, `lti.LineItemMediaType` |
| `PUT /{lineitem}` | `lineitem` | `UpdateLineItem` | 200, `lti.LineItemMediaType` |
| `DELETE /{lineitem}` | `lineitem` | `DeleteLineItem` | 204 |
| `POST /{lineitem}/scores` | `score` | `PostScore` | 204 |
| `GET /{lineitem}/results` | `result.readonly` | `ListResults` | 200, `lti.ResultContainerMediaType` |

A line item belongs to one client: the tool that created it, or whose link you made it for, such as from a Deep Linking `lineItem`. Every hook, reads included, sees only that client's line items and their results; answer another tool's as `ErrLineItemNotFound`. The hooks know a line item by your own id for it, unique in its context, and go-lti answers with its URL, `cfg.LineItemURL`, as its `id`; a result's `scoreOf` is that URL and its `id` the results URL filtered to its user. go-lti checks the scope, the ids in the path, and what the tool sends: a line item needs a label and a `scoreMaximum` greater than 0, and a score needs a `userId`, a `timestamp` and known progress values, with a `scoreMaximum` greater than 0 for a `scoreGiven` of 0 or more. A `scoreGiven` above the maximum is accepted. Bodies over 64 KiB are refused with 413.

```go
handler, err := platform.NewHandler(cfg, platform.Handlers{
	Register:         register,
	AuthorizeService: authorizeService, // as for Names and Role Provisioning Services
	ListLineItems: func(r *http.Request, client platform.ServiceClient, req platform.LineItemsRequest) (platform.LineItemsPage, error) {
		// Check that client may use req.ContextID, then read a page of client's line items in it, filtered by
		// req.ResourceLinkID, req.ResourceID and req.Tag, starting at req.PageToken.
		return platform.LineItemsPage{LineItems: items, NextPageToken: nextPageToken}, nil
		// or platform.ErrContextNotFound (404)
	},
	PostScore: func(r *http.Request, client platform.ServiceClient, req platform.LineItemRequest, score lti.Score) error {
		// Check that the line item is client's and score.UserID a learner in req.ContextID, then keep the score.
		return nil
		// or platform.ErrLineItemNotFound (404), or platform.ErrStaleScore (409) for a score whose
		// Timestamp isn't after the one you have for the line item and user
	},
	// GetLineItem, CreateLineItem, UpdateLineItem, DeleteLineItem and ListResults likewise.
})
```

Every answer has `Cache-Control: no-store`. Errors are OAuth 2.0's JSON error response, as for Names and Role Provisioning Services, and a token or scope refusal carries RFC 6750's challenge; a read of line items asks `AuthorizeService` for `lti.ScopeAGSLineItemReadOnly`, which `lti.ScopeAGSLineItem` also allows. A page is linked to the next as `rel="next"` while your hook returns a `NextPageToken`, keeping the tool's filters and `limit`.

A Deep Linking `ltiResourceLink` can ask for a line item. go-lti checks it has a positive `scoreMaximum` and keeps it as `ContentItem.LineItem`, which decodes into an `lti.LineItem`.

## Errors

A rejection of something a tool or a browser sent is an `*lti.Error` with the spec's error code (such as `invalid_request` or `invalid_redirect_uri`) and a description that is safe to send back. Any other error is your platform's own, such as a signer or network failure.

## Test vectors

`testdata/vectors/` holds JSON cases with their expected results, for JWKS documents, Dynamic Registration requests, Deep Linking responses, custom parameter substitution and the Names and Role Provisioning Services and Assignment and Grade Services launch claims. go-lti's tests run them, and an implementation in another language can run the same cases. See [testdata/vectors/README.md](testdata/vectors/README.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

MIT
