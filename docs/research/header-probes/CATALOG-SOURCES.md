# Header influence catalogue: sources and curation

Research checked on 2026-09-07. The typed recipe TSV contains **216 probe entries and 132 distinct case-insensitive header names**. Multiple literal values are independent probes, not additional header names. It is a curated request catalogue, not a claim of exhaustive market coverage or of vulnerabilities in the products below.

## Wire contract

The resource is UTF-8 TSV with five columns: `name`, `valueKind`, `seed`, `family`, `sourceUrl`; its first line is a comment. Names are case-insensitive. `LITERAL` values must be sent exactly, including quotes, structured booleans and punctuation. TOKEN values use generated markers; `{marker}` in a seed is a grammar-preserving template. URL, HOST and IP use the engine's typed canary generators. Seeds are syntax examples, not credentials or live service addresses.

`Origin` uses a TOKEN template because its grammar permits an origin, not an arbitrary URL path. `Forwarded` uses a template around its host parameter. Fixed trace identifiers are LITERAL: a random free-form token is not a valid UUID, hexadecimal trace context or structured field. `tracestate` is omitted because a valid companion `traceparent` is required; dependencies need a richer engine before adding it. Existing observed headers and technology-specific families precede the remaining catalogue, which now runs in full without a request quota.

## Inventory sources versus executable sources

- [IANA HTTP Field Name Registry](https://www.iana.org/assignments/http-fields) is the standards inventory. Registration alone neither establishes request direction nor makes a safe probe. Follow the linked specification for semantics. The older message-headers registry is not the current HTTP registry.
- [known-http-header-db](https://github.com/pichillilorenzo/known-http-header-db) was inspected, including its README, package metadata, database and license. The fetched `main/dist/db.json` contained **271 names**, of which **84** carry the `request` type. Package metadata reported version **1.0.6**. This is hundreds of names, not thousands. It aggregates MDN, IANA and Wikipedia and is a discovery aid, not evidence that every entry is an active request input.
- The downloaded database SHA-256 was `ab1fb281eaa30ceb5c47bb6fbc3519681d3d4e616f989ca01c85ff78a12fd104`. Upstream `main` is mutable; this hash identifies the inspected bytes. No database descriptions or complete inventory were vendored into the executable resource.
- Upstream database license: [ISC, Copyright 2022 Lorenzo Pichilli](https://github.com/pichillilorenzo/known-http-header-db/blob/main/LICENSE). Future redistribution must retain its copyright and permission notice. Third-party documentation/source licenses remain with their owners; the TSV records factual field names, short protocol values and attribution URLs, not copied documentation prose.
- [MDN HTTP headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers) supplies request direction and links to individual grammars. Each browser entry points to its specific page. Deprecated names remain useful legacy probes; this does not imply current browser support.

## Browser coverage

Client hints were cross-checked against [Chromium's implementation notes](https://chromium.googlesource.com/chromium/src/+/HEAD/components/client_hints/), [Chrome's UA-CH guide](https://developer.chrome.com/docs/privacy-security/user-agent-client-hints) and the [UA Client Hints specification](https://wicg.github.io/ua-client-hints/). Quoted strings, brands and `?0`/`?1` are intentional structured-field syntax. Legacy device/network hints and newer `Sec-CH-*` equivalents are separate names.

Fetch metadata was checked against [Firefox SecFetch.cpp](https://searchfox.org/firefox-main/source/dom/security/SecFetch.cpp) and [WebKit's implementation issue](https://www2.webkit.org/show_bug.cgi?id=246508). These sources support technology coverage, not identical support across every browser/version. The active values are sourced to MDN's field pages.

Raw HTTP mutation can set browser-forbidden headers. A resulting reflection does not establish that an attacker-controlled web page can send that header to a victim's session. Browser reachability, preflight, forbidden headers and actual rendering remain separate exploitability checks. Neither client hints nor `Sec-Fetch-*` presence proves a vulnerability.

## Server and proxy coverage

| Technology | Evidence and catalogue decision |
| --- | --- |
| nginx | [realip module](https://nginx.org/en/docs/http/ngx_http_realip_module.html) documents configurable client-IP fields; includes X-Real-IP and X-Forwarded-For. |
| Apache | [mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html) permits configurable names and trusted proxies. Covered by shared forwarding probes and observed-name discovery; no invented Apache-specific header list. |
| ASP.NET Core | [forwarded header middleware](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-10.0) describes host/scheme/client-IP mutation and original-value bookkeeping. X-Original-* is not automatically treated as an externally trusted input. |
| IIS | [URL Rewrite](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/using-the-url-rewrite-module) supports header-based rules. HTTP_X_ORIGINAL_URL and UNENCODED_URL are server variables; the catalogue does not turn variable names into alleged wire headers. |
| Express | [trust proxy](https://expressjs.com/en/guide/behind-proxies/) ties forwarded host/proto/IP to request properties. Acceptance depends on deployment trust configuration. |
| Django | [settings](https://docs.djangoproject.com/en/5.2/ref/settings/) document forwarded host/port and configurable secure-proxy header. Covered by common forwarding family. |
| Symfony | [proxy configuration](https://symfony.com/doc/current/deployment/proxies.html) includes forwarded prefix affecting generated paths/URLs. |
| Spring | [filters](https://docs.spring.io/spring-framework/reference/web/webmvc/filters.html) documents the forwarding family including X-Forwarded-Ssl and Prefix, and handling of ERROR dispatch. |
| Rails | [RequestId](https://api.rubyonrails.org/classes/ActionDispatch/RequestId.html) describes accepted and sanitized request IDs; expected sanitized echo should remain informational. |

## CDN, tracing and rendering protocols

- [Cloudflare request headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/) and [CloudFront generated headers](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html) establish request-side use. These are often edge-to-origin metadata, overwritten or stripped before the origin. Cataloguing them tests acceptance; it does not assert external controllability. Geographic seeds are independent syntax examples, not a coherent synthetic viewer fingerprint. CloudFront TLS is a protocol/cipher composite; see the literal seed in the TSV.
- [Fastly-Debug](https://www.fastly.com/documentation/reference/http/http-headers/Fastly-Debug/) documents diagnostic response fields enabled by a request value, including retention of surrogate metadata. It also notes cache interaction in chained services. A new debug field alone is not automatically sensitive disclosure.
- [Akamai Pragma diagnostics](https://techdocs.akamai.com/edge-diagnostics/docs/pragma-headers), [Enhanced Debug](https://techdocs.akamai.com/property-mgr/docs/enhanced-debug) and [variable inspection](https://techdocs.akamai.com/property-mgr/docs/test-configs-vars) supply literal activators. Enhanced Debug may require authorization tokens configured by the property; the catalogue does not fabricate tokens. Debug activators need repeatable response-difference evidence, not a reflected marker.
- [Envoy header manipulation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers.html), [Envoy tracing](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/observability/tracing.html), [W3C Trace Context](https://www.w3.org/TR/trace-context/), [W3C Baggage](https://www.w3.org/TR/baggage/), [AWS request tracing](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-request-tracing.html) and [Google trace context](https://docs.cloud.google.com/trace/docs/trace-context) supply typed tracing entries. Sampling-off values are used where available. X-Client-Trace-Id can request sampling according to Envoy configuration; this is an observable side effect. Force-trace, internal-trust flags, certificate identity and original-destination routing are omitted from the catalogue.
- [htmx request header reference](https://htmx.org/reference/#request_headers) supplies eight request fields. Several names also have response uses; request semantics are the inclusion criterion.
- [Inertia protocol](https://inertiajs.com/the-protocol) distinguishes request and response headers. Partial reload fields may need the existing component/version context; isolated probes cannot claim full protocol coverage. Reset, CSRF and validation-action fields are excluded.
- [Turbo frame controller](https://github.com/hotwired/turbo/blob/main/src/core/frames/frame_controller.js) sets Turbo-Frame to the target frame ID.
- [Next.js router header constants](https://github.com/vercel/next.js/blob/canary/packages/next/src/client/components/app-router-headers.ts) distinguish request fields from output markers. Router-prefetch, RSC, segment-prefetch and Next-Url are included. Constants/source branches are mutable; a future update should pin a release and test protocol fixtures. Next-Action, HMR and serialized router-state probing are excluded.

## CMS review

[WordPress authentication](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/) documents X-WP-Nonce as authentication/CSRF context, so it is excluded. [Drupal JSON:API](https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module/api-overview) and [Joomla web services](https://manual.joomla.org/docs/next/general-concepts/webservices/) justify the `Accept: application/vnd.api+json` variant. Joomla's token header and Drupal's CSRF token are excluded. No fictitious product-specific debug fields were added merely to increase the total. Existing custom plugin headers can still be discovered through observed traffic under the engine's exclusions.

## Boundaries and follow-up

This catalogue excludes framing/hop-by-hop fields, transport pseudoheaders, credentials/cookies/CSRF tokens, method override, purge/invalidation triggers and output-only disclosure fields. It does not send CRLF, oversized values, callback addresses or destructive methods. Changing presentation, cache preference or tracing inputs still has operational effects; the engine must enforce scope, safe replay, pacing and cancellation.

The initial schema cannot encode dependencies, version ranges, trusted-proxy conditions or browser reachability. Those limitations are recorded here rather than hidden behind a numerical coverage claim. Before adding each new entry: establish request direction from primary documentation/source, verify grammar and side effects, select a typed generator or literal, attach a direct source, and exercise a local positive and negative fixture. Wider community lists and Reddit can suggest candidates but are not executable evidence. No live website was probed while compiling the catalogue.

## Supplemental name discovery

`header-influence-discovery.tsv` adds 1,073 candidate names from pinned Param Miner and known-http-header-db snapshots. Known response-only fields and authentication, framing, method-override, session and invalidation inputs are filtered. Names without a typed recipe receive an inert random marker and run after the curated families; this proves neither request semantics nor browser support. The combined corpus has 1,155 distinct names (overlap removed), with 216 typed recipes. Unknown name probes can be rejected by parsers; 4xx/5xx are diagnostics; each candidate is now sent individually, and 429/503 pause and retry the pending request.

The reproducible offline importer is `scripts/build-header-influence-discovery.py`. Runtime performs no catalogue downloads. The JAR includes source license notices under `com/b3xal/headeranalyzer/licenses/`. Accept-Encoding is excluded from the active recipe set to preserve transport representation; gzip/deflate response decoding is bounded, while unsupported encodings are explicitly not evaluated for body reflection.

The probe template consistently advertises `Accept-Encoding: gzip, deflate, identity` for both controls and mutations. If the server still returns an unsupported coding, body inspection is explicitly incomplete; response headers remain inspectable. No browser execution or XSS exploitability is claimed.
