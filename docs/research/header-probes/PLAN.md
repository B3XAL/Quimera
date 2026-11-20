# Quimera: header-probe research and plan

> Record of the initial design. The later implementation and its limits are in [IMPLEMENTATION.md](IMPLEMENTATION.md).

Date: 7 September 2026. Audience: development and technical review of Quimera Burp. Status: proposed design; this new battery has not been implemented nor run against external sites.

## Recommended decision

Build a **header influence** discovery and validation module: modify the headers already present and add documented candidates to check what changes in the response. It must combine a versioned catalogue, valid-value generators, differential discovery, reflection detection and independent disclosure detection. XSS confirmation will be a later phase that needs an executable context and a real delivery path to the browser.

Param Miner is a useful base for names and methodology. Greater coverage is not obtained by indiscriminately sending all its entries: it requires knowing request/response direction, syntax, dependencies, technology, trust conditions and values that activate features. The IANA registry is likewise not a list of vulnerable entries. [Param Miner](https://github.com/PortSwigger/param-miner), [IANA HTTP registry](https://www.iana.org/assignments/http-fields).

I interpret the request to exclude 404/401/500 as a filter of **all 4xx/5xx for this module's findings**, both in baseline and in the mutated response. They will be kept as diagnostics, without claiming they are safe: the HTTP status does not prove that an HTML body lacks an executable context. The decisions, limits and severities that follow are engineering proposals, not requirements from the sources.

## 1. What Param Miner actually provides

The official repository has been cloned and read at commit `e43e3b16be11117ed67cfde60e80acf2e95a4adc`. The local count of `resources/headers` gives **1,219 lines, 1,217 unique non-empty entries: 1,212 names with token syntax and five name/value templates**. Separating the templates leaves **1,212 distinct names**. These figures describe that file and revision, not official or verified vulnerable headers.

The five templates are `host~%h:%s`, `origin~https://%s.%h`, `referer~http://%s.%h/`, `x-original-url~/%s`, `x-rewrite-url~/%s`. The importer must keep the value as a template; it must not send the full text as a name. The list also contains fields that are normally response fields, for example `Access-Control-Allow-Origin`. [Reviewed list](https://github.com/PortSwigger/param-miner/blob/e43e3b16be11117ed67cfde60e80acf2e95a4adc/resources/headers).

Reading the code directly shows:

| Piece | Observed function | Application in Quimera |
|---|---|---|
| `ParamAttack` | Calibrates batch size with control responses; incorporates the dictionary and observed words | Adapt batches to real capacity and learn names from traffic |
| `ParamGuesser` | Compares responses, repeats differences, uses permuted names as controls and splits candidate groups | Discover first, isolate later and confirm individually |
| `DiscoveredParam` | Explores the discovered parameter with additional checks | Separate discovery from impact validators |
| `ValueProbes` | Investigates value transformations and other properties | Characterize encoding after finding a signal |

Code sources: [ParamAttack](https://github.com/PortSwigger/param-miner/blob/e43e3b16be11117ed67cfde60e80acf2e95a4adc/src/burp/ParamAttack.java), [ParamGuesser](https://github.com/PortSwigger/param-miner/blob/e43e3b16be11117ed67cfde60e80acf2e95a4adc/src/burp/ParamGuesser.java), [DiscoveredParam](https://github.com/PortSwigger/param-miner/blob/e43e3b16be11117ed67cfde60e80acf2e95a4adc/src/burp/DiscoveredParam.java), [ValueProbes](https://github.com/PortSwigger/param-miner/blob/e43e3b16be11117ed67cfde60e80acf2e95a4adc/src/burp/ValueProbes.java).

I would not automatically carry over its cache-poisoning exploration, external callbacks, special IPs or HTTP framing mutations. These are different reflection/disclosure goals and require their own modules. The advertised figure of up to 65,536 parameters is not a recommended header batch size. [Official Param Miner description](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943).

The repository declares Apache-2.0. The research inventory preserves attribution and the source license file. A future incorporation of code or resources into the product must preserve the applicable notices and document the modifications. [Snapshot license](https://github.com/PortSwigger/param-miner/blob/e43e3b16be11117ed67cfde60e80acf2e95a4adc/LICENSE).

## 2. A broad, traceable and extensible catalogue

Organize four tiers, with visible coverage:

1. **Observed:** real headers from the captured requests; names found in `Vary`, CORS declarations, JavaScript and the target's documentation/API. Those mentions generate candidates, not proof of acceptance.
2. **Documented:** IANA/RFC and official vendor documentation or code; each entry includes syntax and direction.
3. **Dictionaries:** Param Miner seeds, initially pending review. An entry without verified semantics is never activated automatically just by appearing here.
4. **Custom:** names introduced by the analyst or found in local configuration. They are saved with provenance and project scope.

There is no closed inventory covering every deployment: Apache lets you configure `RemoteIPHeader` and Django the header used to determine HTTPS behind a proxy. Therefore, learning from traffic and local extensions are a necessary part of coverage. [Apache mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html), [Django settings](https://docs.djangoproject.com/en/5.2/ref/settings/).

### Verified families and priority

The headers in this table are candidates or documented surfaces; **it is not claimed that they reflect values or leak information in any installation**.

| Family | Examples / triggers | Treatment and primary source |
|---|---|---|
| HTTP and negotiation | `Accept`, `Accept-Language`, `User-Agent`, `Referer`, `Origin`, `Prefer`, conditionals | Per-field semantics; preserve authentication and format. [IANA](https://www.iana.org/assignments/http-fields) |
| Standard proxies | `Forwarded: for=…;host=…;proto=…;by=…` | Modify one parameter at a time and respect quoting/lists. [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239.html) |
| nginx / Apache | `X-Real-IP`, `X-Forwarded-For`, configured name | Acceptance dependent on trusted proxies. [nginx realip](https://nginx.org/en/docs/http/ngx_http_realip_module.html), [Apache](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html) |
| Express | `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-For` | May influence hostname, protocol and IP with `trust proxy`. [Express](https://expressjs.com/en/guide/behind-proxies/) |
| ASP.NET Core | `X-Forwarded-{For,Host,Proto}`, `X-Original-*` | Model configurable names and fields the middleware preserves. [Microsoft](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-10.0) |
| IIS / URL Rewrite | Headers used by rules; variables `HTTP_X_ORIGINAL_URL`, `UNENCODED_URL` | These are documented server variables: do not turn them into input headers without evidence. [IIS](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/using-the-url-rewrite-module) |
| Django / Symfony / Spring | Forwarded family, port, prefix and `X-Forwarded-Ssl` depending on framework | Specific generators; paths and absolute URLs as reflection sites. [Django](https://docs.djangoproject.com/en/5.2/ref/settings/), [Symfony](https://symfony.com/doc/current/deployment/proxies.html), [Spring](https://docs.spring.io/spring-framework/reference/web/webmvc/filters.html) |
| Rails | `X-Request-Id` | Documented sanitized echo: a negative test for false XSS. [Rails RequestId](https://api.rubyonrails.org/classes/ActionDispatch/RequestId.html) |
| Fastly | `Fastly-Debug: 1` | Look for `Fastly-Debug-{Path,TTL,Digest}` and preservation of `Surrogate-Key`/`Surrogate-Control`. [Fastly](https://www.fastly.com/documentation/reference/http/http-headers/Fastly-Debug/) |
| Akamai legacy | `Pragma` with cache/debug directives | Test documented values separately; look for cache-key changes and variables. [Akamai Pragma](https://techdocs.akamai.com/edge-diagnostics/docs/pragma-headers) |
| Akamai Enhanced Debug | `Akamai-Debug` with `cache`, `vars` options | The documented mode requires a token. A rejection or `Akamai-Debug-Status` is not sensitive disclosure. [Enhanced Debug](https://techdocs.akamai.com/property-mgr/docs/enhanced-debug) |
| Cloudflare | `CF-Connecting-IP`, `CF-Connecting-IPv6`, `CF-Pseudo-IPv4`, `True-Client-IP`, `Cf-Ray` | Distinguish client→CDN from CDN→origin; several fields are added or overwritten. [Cloudflare](https://developers.cloudflare.com/fundamentals/reference/http-headers/) |
| CloudFront | `CloudFront-Viewer-*`, `CloudFront-Is-*-Viewer`, `CloudFront-Forwarded-Proto` families | Expand to specific documented names; metadata subject to origin policies. [AWS](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html) |
| Envoy / service mesh | `x-request-id`, `x-client-trace-id`, `x-envoy-force-trace`, `x-forwarded-client-cert`, documented `x-envoy-*` | Internal fields can be sanitized; routing/identity in a specialized profile. [Envoy](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers.html) |
| Traces | `traceparent`, `tracestate`, B3 | Valid IDs, dependencies and hex/enum values; a reflected ID is not a secret. [W3C](https://www.w3.org/TR/trace-context/), [Envoy tracing](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/observability/tracing.html) |
| htmx | `HX-Request`, `HX-Current-URL`, `HX-Prompt`, `HX-Target`, `HX-Trigger`, `HX-Trigger-Name`, `HX-Boosted`, `HX-History-Restore-Request` | Differentiate request from response headers and fragment selection. [htmx reference](https://htmx.org/reference/) |
| Next.js | `rsc`, `next-router-state-tree`, `next-router-prefetch`, `next-router-segment-prefetch`, `next-url` | HTML/RSC variants, dependencies and cache key; versioned profiles. [Next.js CDN caching](https://nextjs.org/docs/app/guides/cdn-caching) |
| Turbo | `Turbo-Frame` | Fragment context, without confusing a partial response with disclosure. [Official turbo-rails code](https://github.com/hotwired/turbo-rails/blob/main/app/controllers/turbo/frames/frame_request.rb) |
| gRPC | HTTP/2 metadata and trailers | Preserve protocol and body; a specific module for binaries and trailers. [gRPC metadata](https://grpc.io/docs/guides/metadata/) |

Later catalogue expansion: HAProxy, Traefik, Caddy, Varnish, F5, Azure Front Door/Application Gateway, API gateways, Kong, Tomcat/Jetty, Laravel, Drupal/WordPress, Java/SOAP, GraphQL, WebDAV and signed APIs. These are **families pending exhaustive curation**, not already-implemented coverage. For each: official documentation → exact names/values → version and conditions → reproducible fixture → incorporation.

### Schema of each entry

```text
id, nameLowercase, displayName, aliases, family, technologies, versionRange
direction: request | response | both | serverVariable | unknown
sourceUrls, sourceRevision, verifiedAt, evidenceLevel, license
valueGrammar, seedTemplates, mutationStrategies, dependencies, conflicts
repeatSemantics, trustBoundary, expectedOverwrites, activationConditions
expectedResponseHeaders, expectedBodyContexts, browserDeliveryConstraints
sideEffects, priority, executionTier, reviewStatus
```

Also store provenance **per trigger**. `Fastly-Debug` and its value `1` are one recipe; `Pragma` with six directives are six variants, not six new headers. Do not collapse hyphen/underscore variants: they are distinct names, even if some infrastructure normalizes them. Case-insensitive for identity, preserving evidence bytes.

The attached CSV is an initial inventory of Param Miner's 1,217 unique entries, normalized with source, template and an `unreviewed` mark. **It is not executable configuration**: all its rows are disabled until reviewed.

## 3. Proposed test engine

### Selection and baseline

Use the captured request, keeping method, path/query, session and body. Automatic start only on eligible GET/HEAD and within scope; HEAD serves for headers, never as a substitute for analyzing the body. Methods with side effects and logout/action paths require explicit test selection. Do not turn a POST into a GET to obtain an apparently cleaner result.

Capture two clean baselines; a third if they disagree. Keep a fingerprint of body structure, MIME, status, headers and session state. Mask demonstrated variation in controls —timestamps, rotating IDs— without hiding new names nor the marker zone. If the session, WAF or backend changes during the sequence, recalibrate with a limited budget or end as inconclusive.

Coverage key: scheme/host/port + method + effective path/query + session context + representation + protocol + catalogue/profile version. Share priorities across paths, but do not automatically share negative results. Show sampled and pending paths; do not call a domain fully tested for having tested its front page.

### Modify existing headers

For a present header, start with individual substitution preserving the grammar; then change a subfield or add a token only where its semantics allow it. The absence of the field can be an additional control, but it is not equivalent to the original control. Restore exactly the captured value between tests.

Keep `Authorization`, `Cookie`, CSRF and signatures as session support by default. Inventory them without altering credentials in the generic battery. `Host`/`:authority`, routing, proxy identity and framing fields have separate profiles: the broad list must not break the transport nor turn the test into another class of audit.

### Add candidate headers

First high-priority observed/documented; then families suggested by technology; finally the reviewed dictionary and deep catalogue. A fingerprint only changes the order, it does not definitively exclude other technologies, since there may be several layers.

Proposed initial batches of 8–16 compatible candidates and a configurable maximum by added bytes, with an initial ceiling of 4 KiB. Large baseline: reduce or test one at a time. On 400/431, a reset or a batch-induced timeout, split/reduce; that result does not prove that no candidate exists nor that all are negative. Do not deliberately seek the server's saturation maximum.

Each header in the batch carries its own marker. A reflection allows direct initial attribution; a change without a marker requires bisection and individual confirmation. Groups with dependencies —for example selecting a mode and providing a value— are tried as an indivisible recipe and then reduced to the minimal causal combination. Bisection of independent headers can miss interactions; record that limitation.

### Value generators

| Type | Proposed strategy |
|---|---|
| Free text / identifier | Random ASCII marker per run/header/variant; at least 96 bits when the format allows it |
| Host / URL | Unique label under `.invalid`, or path/query within the captured origin; do not follow destinations introduced by the probe |
| IP | Pairs of documentation IPs, correlated per run; lower uniqueness compensated with A/B/control |
| Port / boolean / enum | Valid values from the documented domain; do not require reflection of a textual canary |
| Lists / `Forwarded` | Modify one position/parameter and keep the rest |
| UUID / trace | Generate valid UUID/hex and structures with dependencies |
| Debug | Known literal triggers and an off/absent control; do not replace them with random text |
| JSON / router state / binary | Specific parser and serialization; outside the generic mutator |

After a signal: test context-relevant separators **one at a time**, between markers, with size limits. Do not introduce CR/LF in this battery: response splitting is validated structurally in another module. No executable payloads are needed to discover and classify reflection.

### Causal confirmation

Proposed sequence: `C0 → C1 → A → C2 → B → C3`. C are clean controls; A and B are mutations with independent values. Confirm that the reflection follows the value, did not exist in controls and comes from the real response. To trigger disclosure without a marker: repeat the trigger and its absence, checking the presence/type of the sensitive data, not the literal equality of dynamic IDs.

If the marker persists in a control, stop simple attribution: possible cache, storage or session contamination. Record a persistence signal and move to the corresponding validator; do not assume a confirmed vulnerability nor dismiss it as noise.

## 4. Detectors and false positives

### Reflection

Look only in response headers/body/trailers, never in the local copy of the request. First exact match; then explicit and limited transformations. Preserve offsets of the original material and of the decoded content. Do not recursively decode until fabricating a dangerous context the browser would not interpret.

Classify an HTML body into text, attribute, comment, URL and script; plus JSON, XML, text and binary/unsupported content. In headers, distinguish the value of `Location`, `Set-Cookie`, IDs or debug. Decompression and charset with limits, indicating truncation. A response that could not be analyzed does not count as negative.

The need for context is central to the XSS methodology. Therefore, an escaped reflection or a JSON echo is recorded as information; it does not become XSS for containing suggestive characters. [PortSwigger: XSS contexts](https://portswigger.net/web-security/cross-site-scripting/contexts), [OWASP: reflected XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting).

### Disclosure

Compare new headers and semantic changes in existing ones: product/version, internal origin, paths, configuration variables, debug and credentials. Also analyze that data in the body so the result is not limited to headers. Exclude our own values as a supposed leak: reflecting the IP we sent does not reveal an internal server IP.

The appearance of an unknown header is stored as an informational differential; to call it sensitive disclosure the content must be classified and the causality repeated. A cache status or a version does not by itself prove an exploitable vulnerability. [OWASP fingerprinting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server).

Fastly and Akamai justify this detector being independent of the canary: specific triggers can reveal metadata without reflecting the sent value. Fastly also documents cache effects across service chains. Akamai Enhanced Debug requires authentication in its documented mechanism; it must not be presented as a leak without a token by definition. [Fastly-Debug](https://www.fastly.com/documentation/reference/http/http-headers/Fastly-Debug/), [Akamai Enhanced Debug](https://techdocs.akamai.com/property-mgr/docs/enhanced-debug).

### Status filter and error pages

| Outcome | Proposed policy |
|---|---|
| 2xx with body | Evaluate reflection and disclosure; check it is not a login/WAF/soft-404 |
| HEAD / 204 / 205 | Evaluate applicable headers, do not claim body analysis |
| 3xx | Examine headers and `Location`; do not turn a redirect into XSS nor automatically follow the marker URL |
| 304 / 1xx | Do not use as body evidence; obtain a representative baseline or mark as non-evaluable |
| 4xx / 5xx in baseline or variant | Suppress this module's findings and record `suppressed_status` |
| Timeout / reset / truncated response | Inconclusive, never "no vulnerability" |

The requested filter reduces coverage of real error pages. There are also errors served with 200: compare structure and controls, not just status. Do not provoke synthetic 404 paths in ordinary mode.

### XSS and browser delivery

Separate `reflectionConfirmed`, `unsafeContextObserved`, `executionConfirmed` and `deliveryConfirmed`. Burp can write headers that an attacker page cannot set arbitrarily. Fetch restricts `Host`, `Origin`, `Cookie`, `Referer`, `Sec-`/`Proxy-` prefixes, among others; other headers require a preflight depending on name and value. These restrictions do not eliminate possible chains, but they prevent inferring delivery by link. [Fetch Standard](https://fetch.spec.whatwg.org/#forbidden-request-header).

A Fetch response does not automatically become an executed document. The later confirmation must demonstrate a navigation/resource/DOM sink or a real cache chain, under the original origin, MIME, CSP, `nosniff` and disposition. Running a saved response in a local HTML file or changing its MIME does not confirm the original finding. The MVP will not publish "confirmed XSS".

## 5. Cache and effective traffic control

A uniform cache-buster within each comparison, distinct between experiments. Validate that it does not alter functionality and that it truly separates representations; a random query and `no-cache` are not a guarantee of isolation. Multiple caches, fragments and parameters excluded from the key can hide or propagate signals. [PortSwigger: cache poisoning](https://portswigger.net/web-security/web-cache-poisoning), [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement).

If isolation is not verified, allow only harmless discovery with an explicit diagnostic; mutations that alter output must acknowledge that even harmless markers can persist. The deliberate confirmation of cache poisoning belongs to a separate phase: an isolated resource, a clean request without the candidate header, a distinct resource control and reproduction. `X-Cache: HIT` on its own does not confirm it.

Before expanding the number of probes, implement a truly shared limiter. In the local code, `ThrottledRequestSender.send()` calls `directSend()` when `engineReady == null`; the normal path does not initialize the resource-pool engine. Its comments explain that it is disabled due to previous deadlocks. The class name does not prove traffic regulation.

Proposed initial values to calibrate in the lab:

- Concurrency 1 per origin and 4 global; 1 request/second per origin, 4/second global, with a budget shared between modules.
- Automatic profile: 100 requests per context/path, counting controls, retries and confirmations.
- Deep manual profile: up to 2,000 per context/path, extensible by configuration and with pause/resume. It does not guarantee exhausting the catalogue.
- Reserve a part of the budget for confirmation; when exhausted, `partial_budget`, not "safe".
- Honor `Retry-After` and apply backoff/pause after 429, 503 or sustained degradation; no unlimited retries.
- Initial analysis maximum: 2 MiB of decompressed body per response and 20 MiB of evidence per job, configurable; mark what is not analyzed.
- Cancellation: no new requests after cancelling; record those already in flight and the real API limit to abort them. Do not promise immediate interruption if Montoya does not offer it.

Illustrative cost: 1,217 independent candidates at 16 per batch require at least 77 discovery requests; controls, semantic variants and confirmation add to that. In the worst case, with numerous differences or rejected batches, bisection loses its advantage and the cost approaches the individual one. The budget is more useful than promising a fixed time.

## 6. Fit with the current code

Local inspection, not inference from external documentation:

| Existing component | Proposed integration |
|---|---|
| `analyzer/ActiveHeaderScanner.java` | Orchestrate the new module without adding hundreds of conditions to the current scanner; reuse useful rules from the Cache/CDN probe |
| `proxy/QuimeraHttpHandler.java` | Independent bounded queue, scope, per-context deduplication and a guard against recursion |
| `util/ThrottledRequestSender.java` | A real limiter for the direct path, shared by all probes; preserve failure diagnostics |
| `model/UrlAnalysisResult.java` | Reuse `probeExchanges` and labels; add a structured probe descriptor and preserve metadata when copying/persisting |
| `model/HeaderFinding.java` | Separate sent header name, reflected location and evidence class |
| `model/DomainData.java` | Aggregate disclosure without losing provenance or causality of each path |
| `scanner/NativeProbeIssuePublisher.java` | Do not publish every echo just for being `CERTAIN`; introduce a publishability criterion and probe identity |
| `ui/DetailPanel.java` / retest | Show A/B/controls, context, coverage and re-run only the causal recipe |

Proposed new classes: `HeaderCandidateCatalog`, `HeaderValueGenerator`, `HeaderProbePlanner`, `HeaderInfluenceProbe`, `BaselineComparator`, `ReflectionAnalyzer`, `DisclosureDeltaAnalyzer`, `ProbeEvidence`, `ProbeCoverage` and `ProbeRateLimiter`. Indicative names, adjustable to the repository's style.

The recursion guard must identify all of the module's exchanges, including controls. Prefer local request correlation; if a marker header is needed, check that this header is not itself the cause of the echo. Do not allow probe responses to feed back into unlimited auto-discovery.

Do not store only a `Map<String,String>` for evidence: keep an ordered list with multiplicity, especially `Set-Cookie`, `Warning`, repeated fields and trailers. Deduplicate by path/context/header/mutation/result class; rotating the canary does not generate a new issue. When reopening a project or updating the catalogue, distinguish historical evidence from recent verification.

### Severity and presentation

| Evidence | Proposed outcome |
|---|---|
| Unexplained status/size difference | Influence diagnostic; not a vulnerability |
| Confirmed echo, ID, escaped HTML, JSON/text | Info, confidence according to repetition |
| Relevant characters unescaped | Potentially unsafe context, pending validation; no automatic promotion to XSS |
| Confirmed disclosure | Classify the data and keep Quimera's existing policy; do not confuse severity with exploitation |
| Demonstrated execution and delivery | Confirmed XSS, severity according to impact |

There is a compatibility decision: `Severity.java` currently classifies a product family as Low and an exact version as Medium. This project must not implicitly downgrade those findings globally. I recommend keeping that policy when reusing rules, labeling "disclosure" clearly and keeping the new echoes at Info. If a change to the global fingerprinting policy is decided, do it as a separate, tested change.

In the UI: "Reflection", "Disclosure", "Influence", "Pending confirmation"; detail with original/mutated request, header and subfield, A/B/controls, MIME/status, fragment and offsets, encoding, delivery conditions, recipe and references. Coverage: reviewed, tested, confirmed, suppressed by status, inconclusive and pending. Negative result: **"No signal in the tested variants"**.

## 7. Implementation plan by deliverables

| Order | Deliverable | Exit criterion |
|---|---|---|
| 1 | Catalogue schema and seed importer; initial curation | Per-row provenance, name/template separation, direction and revision; no pending candidate runs |
| 2 | Scheduler/limiter/cancellation and coverage model | Effective budgets on the direct path, without recursion and without blocking Swing/proxy |
| 3 | Baselines, controls, individual mutation of existing headers and reflection | Reproducible A/B/control; correct encoding and status; Info echoes |
| 4 | Differential disclosure, Fastly and Akamai expansion | Documented causal triggers; integration without duplicating the existing cache battery |
| 5 | Discovery of new headers by batches and bisection | 400/431 cases, multiple candidates and dependencies resolved; partial coverage visible |
| 6 | Proxy/framework/CDN profiles and traffic learning | Each recipe documented with a fixture and grammar; a fingerprint only prioritizes |
| 7 | UI, persistence, retest and native publishing | Complete evidence; recipe retest; Info does not flood Issues; no loss after reopening |
| 8 | Complex contexts, trailers/gRPC and catalogue expansion | Supported paths/protocols declared and negative tests per family |
| 9 | Browser XSS confirmation and cache chains, as an expansion | Real execution and delivery demonstrated in the lab; no promotion by regex |

First useful version: deliverables 1–4 and the minimal UI/evidence needed from 7. It discovers the headers already in use and the known disclosure recipes. Second version: 5–7 complete and systematic curation. Third: expansions 8–9. Do not postpone traffic limiting or controls until after the big dictionary.

## 8. Validation matrix

Unit tests for parsers/generators/comparators and a local HTTP lab with controlled responses. Then representative framework/proxy/CDN fixtures via documented emulation; use one's own real services when it is necessary to check managed behavior an emulation does not demonstrate.

| Case | Expected outcome |
|---|---|
| Normal sanitized `X-Request-Id` echo | Info, no XSS |
| Marker in escaped HTML, JSON or text | Correct context; no execution nor MIME change |
| Marker in attribute and script | Correct location/encoding; execution pending |
| Marker present only in request/local evidence | No reflection finding |
| Debug header also appears in controls | Do not attribute activation to the mutation |
| IP/hostname sent by the probe returns in the response | Reflection, not an internal leak |
| New internal header reproducible only with the trigger | Causal disclosure |
| 401/404/500 or error baseline | Suppressed by policy, kept in coverage |
| WAF/login/soft-404 with 200 | Do not confirm just by length/canary of a block page |
| Batch rejected with 431 | Reduce/split; do not mark everything as negative |
| Two causal headers or a two-field dependency | Identify both / the minimal recipe, without arbitrary attribution |
| Brotli/gzip/charset/huge body | Decoding supported and bounded; truncated/inconclusive made explicit |
| Repeated header/trailer | Preserve multiplicity and location |
| Cache ignores the query buster / marker persists | Isolation not confirmed; route to persistence diagnostic |
| Arbitrary header injectable only by Burp | Reflection confirmed, browser delivery not confirmed |
| Cancellation, extension unload, full queue, 429 | No new jobs, coherent backoff and resumption |
| Reopen project / repeat with a new canary | Same finding identity and recoverable evidence |

Acceptance metrics: zero false XSS on negative fixtures; all known positive recipes detected in their context; request count within budget; percentage of curated catalogue and of executed variants reported separately; p50/p95 cost per context measured in the lab. Do not announce universal coverage from fixtures.

## 9. Scope and limits of this research

Primary sources from standards, vendors and frameworks, Param Miner code and local Quimera components were reviewed. Reddit was consulted as a hint about identifier echoes and context difficulties; the technical decisions rely on documentation and proposed tests, not on votes or forum conclusions. Example hints: [X-Correlation-ID echo](https://www.reddit.com/r/bugbounty/comments/1g23wzs), [questions about wordlists/cache-busters in Param Miner](https://www.reddit.com/r/bugbounty/comments/1jw8623).

The Fastly check was completed by downloading the official page because the web reader returned an unsupported content type. Not all versions of the technologies have been checked at runtime nor have the 1,217 seeds been semantically curated. The research is enough to fix the architecture, controls, first recipes and expansion process; a promise of "every header on the market" would not be verifiable.

The definitive catalogue will grow through maintenance: reviewing changes in sources and versions, keeping removals/deprecations, testing new recipes on fixtures and publishing coverage metrics. The most important source for private headers will remain the target's traffic and configuration.
