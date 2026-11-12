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

## `registration_response/`

The response to a Dynamic Registration `request` that the platform registered with `grant`: its
`client_id`, `deployment_id`, and the `scopes` and `claims` it granted. The response's `scope` and
`claims` are what the tool asked for narrowed to the grant. `registration_client_path` is
`Paths.RegistrationClient` under platform issuer `https://platform.example.com/lti`, or `null` for a
platform that doesn't serve the client configuration endpoint. `expect_response` is the response
body: with `registration_client_uri`, the issuer plus the path plus `/{client_id}`, when the
platform serves the endpoint, and without it otherwise.

## `registration_client/`

A tool's request to its client configuration endpoint (LTI Dynamic Registration 1.0 §4), at platform
issuer `https://platform.example.com/lti` with `Paths.RegistrationClient` `/registrations`. The
tool is client `client-1`, whose access token was granted `scopes`. `registered` is its
registration request as the platform keeps it, any pending update applied, and `grant` is what the
platform granted, as in `registration_response/`. `method` is `GET` or `PUT`, with the PUT's
`body`, at the endpoint of `path_client_id`. A PUT's update is kept pending and the answer reflects
it. `expect_status` is the answer's status: a success has `expect_body`, the registration in the
registration response's shape with `client_id` and `registration_client_uri`; a refusal has the
OAuth 2.0 `error_code` and its `error_description`, if any. A GET needs `registration.readonly` or
`registration`, and a PUT `registration`. A PUT body is checked as a registration request is, with
the same errors, and refused when its `client_id` isn't the tool's own. Another client's endpoint
is a 404.

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

An `ltiAssetProcessor` item may be returned only when `accept_types` offers it. Its `custom` and
its `report.custom` are optional, and a missing or `null` object means no parameters, but their
values are strings, possibly empty, and never `null`.

A valid case has the number of `items` returned. An invalid case has the `error_code` and a
substring of its `error_description`. Every item URL must be https (LTI 1.3 §3.5); items needn't
be on the tool's domains.

## `ags_endpoint/`

A launch message and the Assignment and Grade Services endpoint it is sent with. `message_type` is
`LtiResourceLinkRequest` or `LtiDeepLinkingRequest`, `context` is the launch's context claim, if
any, and `ags_endpoint` is the `scope`, `lineitems` and `lineitem` the platform sets, if any. A
valid case has `expect_claim`: the `https://purl.imsglobal.org/spec/lti-ags/claim/endpoint` claim
the launch sends, or `null` when it sends none. An invalid case must be refused: the claim needs a
context (AGS 2.0 §3.1), at least one scope, only AGS scopes, and a `lineitems` or `lineitem` URL,
each an absolute https URL. A Deep Linking request launches no resource, so it can't carry a
`lineitem`.

## `names_role_service/`

A launch message and the Names and Role Provisioning Services URL it is sent with. `message_type`
is `LtiResourceLinkRequest` or `LtiDeepLinkingRequest`, `context` is the launch's context claim, if
any, and `context_memberships_url` is the URL the platform sets, if any. A valid case has
`expect_claim`: the `https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice` claim the
launch sends, or `null` when it sends none. An invalid case must be refused: the URL belongs to the
launch's context (NRPS 2.0 §3.6.1.1), so a launch without a context can't have one, and it must be
an absolute https URL.

## `platform_notification_service/`

A launch message and the LTI Platform Notification Service claim it is sent with. `message_type` is
`LtiResourceLinkRequest` or `LtiDeepLinkingRequest`, and `platform_notification_service` is the
`platform_notification_service_url` and `notice_types_supported` the platform sets, or `null` for
none. A valid case has `expect_claim`: the
`https://purl.imsglobal.org/spec/lti/claim/platformnotificationservice` claim the launch sends, with
`service_versions` `["1.0"]`, the `noticehandlers` scope, and `notice_types_supported` as `[]` when
the platform sends none; or `null` when it sends no claim. An invalid case must be refused: the URL
must be an absolute https URL.

## `notice_handlers/`

A tool's request to its notice handler registration endpoint, with the platform's supported
`notice_types`, the tool's `redirect_uris` and `domains` (its domain, then its secondary domains),
the `scopes` its access token was granted and the handlers already `registered` for client
`client-1` and deployment `deployment-1`. `method` is `GET` or `PUT`, with the PUT's `body`.
`expect_status` is the answer's status: a success has `expect_body`, and a refusal has the OAuth 2.0
`error_code` and, for a 400, its `error_description`. A GET lists every supported type, in order,
with `""` where no handler is registered. A PUT is refused for an unsupported type, a handler that
isn't an absolute https URL on the tool's own domain, and a `max_batch_size` that isn't a positive
integer. The tool's own domain is exactly the host of one of its redirect URIs or its domain:
subdomains are other hosts, secondary domains don't count, and port, path and case don't matter. An
empty handler removes the type's handler.

## `notice/`

A notice the platform signs for tool `client-1` as platform issuer
`https://platform.example.com/lti`, product `platform-1` (`Example LMS`, family `example`, version
`1.0.0`). A valid case has `expect_claims`: the notice JWT's claims without `iat`, `exp` and
`nonce`, which are new on every signature. The notice's `timestamp` keeps its time zone and is
written to the millisecond. An invalid case must be refused: a notice needs a `deployment_id`, an
`id`, a `type` and a `timestamp`.

## `asset_processor_launch/`

An Asset Processor launch, laid out as id_token claims for tool `client-1` in deployment
`deployment-1`. `message_type` is `LtiDeepLinkingRequest`, `LtiAssetProcessorSettingsRequest`,
`LtiReportReviewRequest` or `LtiEulaRequest`, and `message` holds what the platform sets: the
Deep Linking request's `accept_types`, the `context`, `roles`, `sharing`, `custom` and
`context_memberships_url`, and the message's own `activity`, `for_user`, `submission`, `asset`,
`assetreport_type` and `eulaservice`. A valid case has `expect_claims`, claims the launch must send
with exactly these values, and `expect_absent`, claims it must not send. An invalid case must be
refused:

- a Deep Linking request that offers `ltiAssetProcessor` needs the `activity` claim;
- a settings launch needs a context and the activity's id;
- a report review needs a context, the activity's id, the owner's `user_id`, the submission's and
  the asset's ids and the report type, and has no resource link. The owner's name and email address
  are sent only when `sharing` allows them;
- a EULA launch needs the EULA service, an absolute https URL with one or both of the two EULA
  scopes. It carries no context services, and without a context no context roles.

## `asset_processor_submission/`

An `LtiAssetProcessorSubmissionNotice` the platform signs for tool `client-1`, as in `notice/`.
`submission` is the notice's `deployment_id`, `id` and `timestamp`, the `sub` and `roles` of a user
who submitted for the owner, if any, the `context`, the owner in `for_user`, the `activity`, the
`submission`, the owner's current `assets`, the `report_url`, if any, and the processor's `custom`.
A valid case has `expect_claims`, as in `notice/`: the `assetservice` claim carries the
`asset.readonly` scope and the `assetreport` claim the `report` scope. An invalid case must be
refused: a notice needs the context, the owner's `user_id` and the activity's and submission's ids,
a `sub` needs `roles`, and each asset needs a unique id, an absolute https URL, its SHA-256 digest
in base64, its upload timestamp and its content type.

## `asset_service/`

A tool's GET of an asset from the Asset Service, at platform issuer
`https://platform.example.com/lti` with `Paths.Assets` `/assets`, so the asset's URL is
`https://platform.example.com/lti/assets/{asset_id}` with `asset_id` path-escaped. The tool is client
`client-1`, whose access token was granted `scopes`. `asset` is what the platform has for the id:
its `content_type` and `content`, or the `redirect_url` of the storage it is in, or `null` for an
asset it doesn't have or that isn't the tool's. `expect_status` is the answer's status: a 200 has
the asset's `expect_content_type` and `expect_body`, a 302 has `expect_location`, and a refusal has
the OAuth 2.0 `error_code`. The service needs the `asset.readonly` scope.

## `asset_report/`

A tool's POST of one report to a processor's report URL with the Asset Report Service, at platform
issuer `https://platform.example.com/lti` with `Paths.AssetReports` `/asset-reports`, so the URL is
`https://platform.example.com/lti/asset-reports/{processor_id}`. The platform has processor
`processor-1` only. The tool is client `client-1`, whose access token was granted `scopes`, and
`body` is the report. `expect_status` is the answer's status: a 200's body is the report as the
tool sent it, and `expect_report` is the report as the platform reads it, written back with its
timestamp to the microsecond. A refusal has the OAuth 2.0 `error_code` and, for a 400 or 404, its
`error_description`.

The service needs the `report` scope. A report needs `assetId`, `type`, `timestamp`, a `priority`
from 0 to 5 and `processingProgress`, and each member must have its JSON type. Reading is
otherwise lenient: an unknown `processingProgress` is `NotReady`, an `errorCode` may be the tool's
own, `result` and `indicationAlt` aren't cut, a `timestamp` may have any precision, a basic offset
or no time zone (UTC), and a `priority` may be a whole float. An `indicationColor` needs its
`indicationAlt`. Every other member, such as one named after the tool's domain, is
kept as it is.

## `eula_service/`

A tool's request to a deployment's EULA service, at platform issuer
`https://platform.example.com/lti` with `Paths.Eula` `/eula`, so the service is
`https://platform.example.com/lti/eula/{deployment_id}` and the request goes to its `/{endpoint}`,
`user` or `deployment`. The platform has deployment `deployment-1` only. The tool is client
`client-1`, whose access token was granted `scopes`; `method` is `POST`, `DELETE`, `PUT` or `GET`,
with the request's `body`, if any.

`expect_status` is the answer's status: a 200 has `expect_body`, the object the tool sent, and a
refusal has the OAuth 2.0 `error_code` and, for a 400 or 404, its `error_description`.
`expect_hook` is what the platform was asked to do: `record_acceptance` with the acceptance (its
timestamp written to the millisecond), `clear_acceptances`, or `set_eula_required` with the
setting; a case without it asks nothing. `POST /user` takes `{userId, accepted, timestamp}`, all
required, and `DELETE /user` clears every user's acceptance, both with the `eula/user` scope;
`PUT /deployment` takes `{eulaRequired}`, required, with the `eula/deployment` scope. There is
nothing to GET. A timestamp without a time zone is UTC.

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
