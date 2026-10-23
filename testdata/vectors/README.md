# Test vectors

Plain JSON cases with their expected results, so that go-lti's tests and an LTI implementation in
another language can run the same cases. Each file is one case with a `description` and `valid`.

## `jwks/`

`jwks` is a JSON Web Key Set as a tool publishes it. A valid case lists the `kids` of the RS256
signing keys that must be kept, in order; every other key must be skipped. An invalid case must be
rejected as a whole.

## `registration/`

`request` is a Dynamic Registration request body (LTI Dynamic Registration 1.0 §3.1). A valid case
has `expect`: the tool's `domains`, whether it `requests_name` or `requests_email`, and its
localized `client_names`. An invalid case has the RFC 7591 `error_code` to answer with.

## `deep_linking/`

`claims` is the payload of an LtiDeepLinkingResponse, without `iat` and `exp`. Sign it with RS256
using a key from the tool's JWKS, setting `iat` and `exp` to the current time plus
`iat_offset_seconds` and `exp_offset_seconds`; a `null` offset leaves the claim out. Verify it with:

- platform issuer `https://platform.example.com/lti`;
- tool `client_id` `client-1`, deployment `deployment-1` and domains `["tool.example.com"]`;
- the Deep Linking settings in `session`: `accept_types`, `accept_multiple` and `data`.

A valid case has the number of `items` returned. An invalid case has the `error_code`.
