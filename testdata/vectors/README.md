# Test vectors

Plain JSON cases with their expected results, so that go-lti's tests and an LTI implementation in
another language can run the same cases. Each file is one case with a `description`, and a `valid`
where the case can be refused.

## `jwks/`

`jwks` is a JSON Web Key Set as a tool publishes it. A valid case lists the `kids` of the usable
RS256 signing keys, in order. Every other key must be skipped, as RFC 7517 §5 asks: other types and
algorithms, encryption keys, and RS256 keys that are malformed, padded (base64url has no padding,
RFC 7515 §2), outside 2048 to 4096 bits, or have an invalid exponent. An invalid case is a set with
no usable key.

`invalid-security-framework-example.json` is the 1EdTech Security Framework §6.3 example set. Its
`n` values are padded, so it is refused on purpose: go-lti follows the spec text over its example.

## `registration/`

`request` is a Dynamic Registration request body (LTI Dynamic Registration 1.0 §3.5.2). A valid
case has `expect`: the tool's `domains`, whether it `requests_name` or `requests_email`, its
localized `client_names`, the login, redirect and launch URIs that are `off_domain_uris`, and the
`public_suffix_domains`. An invalid case has the RFC 7591 `error_code` to answer with and a
substring of its `error_description`.

The spec's own request examples spell the grant `"implict"` and have a trailing comma.
`invalid-spec-example.json` is the §3.5.2 example with only the comma removed, and it is refused on
purpose for the typo: the grant type is `implicit`. `valid-spec-example-with-implicit.json` also
corrects the typo.

## `authentication_request/`

`form` is the tool's OIDC authentication request to the authorization endpoint, as form values
(each a list, since a parameter may be repeated). A valid case must parse; an invalid case has the
`error_code` to answer with and a substring of its `error_description`.

## `deep_linking/`

`claims` is the payload of an LtiDeepLinkingResponse, without `iat` and `exp`. Sign it with RS256
using a key from the tool's JWKS, setting `iat` and `exp` to the current time plus
`iat_offset_seconds` and `exp_offset_seconds`; a `null` offset leaves the claim out. Verify it with:

- platform issuer `https://platform.example.com/lti`;
- tool `client_id` `client-1`, deployment `deployment-1` and domains `["tool.example.com"]`;
- the Deep Linking settings in `session`: `accept_types`, `accept_multiple` and `data`.

A case taken from the spec carries its own `platform_issuer`, `client_id` and `deployment_id`.

A valid case has the number of `items` returned. An invalid case has the `error_code` and a
substring of its `error_description`. Every item URL must be https (LTI 1.3 §3.5); items needn't
be on the tool's domains.

## `substitution/`

A launch message and the `custom` parameters it is sent with, as configured. `message_type` is
`LtiResourceLinkRequest` or `LtiDeepLinkingRequest`; `sub`, `context`, `resource_link`, `locale`
(the launch presentation's) and `user` are what the message carries, `sharing` says whether the
user's `name` and `email` may be shared, and `variables` are the values the caller supplies for
variables the message doesn't carry. `expect_custom` is the custom claim the launch sends. Only a
value that is exactly `$` and a variable name is substituted. A variable the platform supports
(`User.id`, `Person.name.full`, `Person.name.given`, `Person.name.family`, `Person.email.primary`,
`Context.id`, `Context.title`, `Context.label`, `ResourceLink.id`, `ResourceLink.title`,
`ResourceLink.description` and `Message.locale`) takes the message's value, else the supplied
one, else an empty string (LTI 1.3 Appendix B). Any other variable takes the supplied value or
stays as it is. A variable about the user that `sharing` doesn't allow takes an empty string
instead of its value: `Person.name.*` and `User.username` need `name`, `Person.email.*` needs
`email`, and the other `Person.*` variables are always empty, or stay as they are when not
supplied. Every case is valid.
