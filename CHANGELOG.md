# Changelog

## 1.0.1 - unreleased

- Evidence navigation and disclosure-aggregation improvements across the Logger and Cookie views,
  including new domain-level disclosure inventory and per-URL analysis results.
- Cache diagnostics: shared-cache evidence detection, cache-key disclosure probing and
  cache miss/hit transition tracking in the active scanner.
- Confirmed active-probe findings (cache-key disclosure, CORS reflection, TRACE, HSTS) now also
  publish to Burp's native Issues tab, not only Quimera's own Logger. Previously only Category.AUTH
  findings reached native Issues, so an active probe result (real diagnostic traffic sent, real
  response verified, Confidence.CERTAIN) was invisible outside Quimera's own UI even though it is
  exactly the kind of high-confidence finding native Issues is for. Uses its own dedup namespace so
  a same-titled but weaker passive sighting (HeaderPassiveScanner, fires synchronously on ordinary
  traffic) can no longer claim the slot first and silently block the probe's own, stronger evidence
  for a different URL from ever reaching native Issues.
- Fixed: the active-probe native-Issues dedup key above was still keyed by host only, not by URL.
  Once one URL on a host published a cache-key disclosure (or MISS-to-HIT transition) finding
  under a given title, every other URL on that same host with the same finding title was silently
  dropped, e.g. a cache-key probe that fired successfully across ten different endpoints on one
  host but only ever surfaced one native Issue. Quimera's own Logger already showed every affected
  URL correctly; only the native Issues publishing path collapsed them. Now keyed by the full URL,
  so each distinct affected endpoint gets its own native Issue.
- Cache-key disclosure is now also detected passively on every observed response (not only on
  the active scanner's own replay), so a key already echoed in ordinary traffic is reported even
  when auto active scan is off and no explicit probe ran.
- Cache-key active probe now sends each debug Pragma token in its own isolated request, beginning
  with the exact `Pragma: x-get-cache-key` value used by strict implementations and PortSwigger
  Academy. It replaces a captured browser `Pragma: no-cache` instead of merging it, and detects
  disclosed cache-key headers on redirects/errors as well as 2xx responses.
- Automatic cache-key probing now has its own high-capacity queue, runs before the slower CORS/
  TRACE/HSTS battery, and covers every observed URL even when normal content-type/extension
  filters skip that response. Mutating and WebSocket-shaped captures are sanitized into safe GET
  probes while retaining authentication headers and cookies.
- Cache-key coverage follows the general Auto Active Scan toggle and runs once per URL, gated on
  cache evidence at the HOST level: once any response on a host shows a real cache signal, every
  other URL on that host becomes eligible too, not only the individual response that showed it.
  The general auto-scan dedup now logs a one-time `auto active scan: N probe(s) for <url>` line
  the first time each URL is actually probed, so "ran and found nothing" is distinguishable from
  "never ran" in Output/Errors; later duplicate sightings of an already-scanned URL are silent, not
  one log line per repeat request on a busy or dynamic site.
- Fixed a real root cause of cache-key (and other) findings appearing to vanish or get replaced by
  an unrelated request: UrlAnalysisResult.path (and therefore the Logger row/IssueGroup identity)
  came from a helper that strips the query string, so /post?postId=4, /post?postId=5, and even an
  unrelated 404 to bare /post all collapsed onto the exact same row, each later sighting silently
  overwriting the previous one's stored request/response and findings. Row identity now includes
  the query string.
- Fixed Burp's final scanner consolidation callback, which still returned KEEP_EXISTING solely
  when issue titles matched. The first cache-key issue (commonly the 404 academyLabHeader probe)
  therefore suppressed every later 200 issue even after publisher deduplication was corrected.
  Consolidation now requires both the issue title and exact affected URL to match.
- Infrastructure cookie catalog and filtering (F5, and related infra cookies) added to
  CookieAnalyzer to reduce noise from non-application tracking cookies.
- Expanded unit test coverage for the above (cache probes, cookie catalog, evidence search,
  domain disclosure inventory).
- Added a WebDAV probe (OPTIONS request checking for `DAV`/`MS-Author-Via`) to the active scanner
  battery, alongside cache-key, CORS, TRACE and HSTS.
- Cache-key transition evidence now shows a clean before/after pair: a genuine cache MISS request
  first, then an identical clean replay confirming the HIT, instead of the internal cache-busting
  and debug-Pragma probe traffic used to detect the behavior in the first place. The replay only
  reuses a captured request verbatim when it is a GET, otherwise it falls back to a synthetic GET
  so a mutating request is never resent.
- Findings and their evidence requests now persist in the Burp project and survive closing and
  reopening it, instead of resetting to empty. Capped per host and finding type (200 stored
  request/response pairs) so a header seen on thousands of URLs does not bloat the project file;
  the finding count itself is not capped, only how many request/response pairs are kept as
  evidence.
- Moved that persistence work off the HTTP handler and UI thread onto its own background queue,
  and reviewed the extension end to end against Burp's official BApp Store acceptance criteria.
- Removed verbose per-attempt debug logging from the cache-key and cache-buster probes, keeping
  only the essential startup and outcome log lines.
- Expanded credential/secret detection after a gap analysis against TruffleHog's public detector
  set: added recognition for Auth0, Okta, OneLogin, Discord, Digital Ocean, Docker Hub, Figma,
  Notion, PlanetScale, Sentry, Shopify, Supabase and Cloudinary, plus new value-shape signatures
  for Twilio Account SIDs, OpenAI project keys and npm tokens. Scope stays detection-only (regex
  and context matching), no active third-party verification calls.
- Fixed a host-wide view's Cookies section never matching the header finding actually selected in
  the Logger; host-wide cookie aggregation now mirrors the same pattern already used for header
  disclosure findings.
- Fixed a small number of header disclosure checks being skipped entirely on responses excluded by
  the content-type/extension filter; that filter now only skips the (expensive) body-parsing
  pipeline, header-only disclosure checks still run.
- Fixed `TechFingerprinter` asserting a fixed vendor (Fastly) for generically-named headers like
  `X-Served-By`/`X-Timer` regardless of the actual value shape, which produced wrong technology
  attributions on non-Fastly infrastructure.
- Fixed a duplicate finding for the same Akamai/Fastly cache-debug headers being raised from two
  separate rule sources at once.
- Fixed `JScrollPane` mouse-wheel scrolling being uncomfortably slow across most of the UI (Logger,
  Cookies, Detail/Advisory, Rules and several dialogs), Swing's default unit increment is only a
  few pixels per notch.
- Investigated routing every request Quimera itself sends through Burp's own project-configured
  resource pool (Project options / Resource Pool / Default) via Montoya's
  `RequestExecutionEngine`, so a slow/careful request rate set for a sensitive target would apply
  to Quimera's probes too. Two different, independently documented usage patterns were tried and
  both confirmed live to hang forever: "streaming" (a custom `RequestSource`) and "reactive"
  (seed + `RequestExecution.queue()`, no `RequestSource` at all). Every active-probe request paid
  a 60s timeout before falling back on the second attempt, which made an entire probe battery take
  minutes instead of being instant. Two structurally different patterns failing identically is
  strong evidence the problem is in `RequestExecutionEngine` itself on the tested Burp install (a
  brand new API, introduced 2026.7), not in how this was being called. Disabled again; every
  request sends directly, exactly as before any of this existed. Worth reporting to PortSwigger;
  the groundwork and its tests stay in the codebase for if that ever gets resolved.
- Fixed a real, live-confirmed performance regression: passive analysis for every response
  (header-only for filtered/static content types, the full body-based pipeline otherwise,
  including every probe it can trigger: Google key verification, the non-cache active battery,
  JWT active probe, session invalidation) ran synchronously on Burp's own response-handling
  thread, delaying the browser from getting the response it was waiting on. Confirmed live on an
  asset-heavy page (dozens of JS/CSS/font requests) that loaded instantly with Quimera unloaded
  and visibly stalled with it enabled. Both paths now run on a dedicated background executor
  (`Quimera-Analysis`); the response is handed back to the browser immediately regardless of how
  long Quimera's own analysis takes.
- Fixed roughly two dozen call sites across the extension calling `api.logging()` directly instead
  of through the existing `SafeLogging` helper, found live via an uncaught `NullPointerException`
  when Burp's own logger became briefly unavailable. `SafeLogging` already existed specifically to
  guard against this; these call sites had simply never been switched over to it.
- Split credential/leak body scanning (`CredentialBodyAnalyzer`, by far the most CPU-expensive
  check in the whole pipeline: around two dozen regex signatures plus provider/context matching
  over the full request+response body, run on every JS/CSS response, not only HTML) out of the
  main per-response analysis and onto its own dedicated, single-threaded queue
  (`Quimera-Leaks`). The rest of the passive analysis (headers, cookies, JWT recognition, tech
  fingerprinting) stays on its own faster, multi-threaded queue and is never held up waiting for
  leak-scanning to keep up with traffic; a busy asset-heavy page can no longer make Quimera
  consume more CPU than a single core's worth of leak-scanning at a time. Leak findings still
  reach the same Logger/Cookies row and native Issues, just a little behind live traffic on a busy
  site, which is expected and fine. The bulk "Analyze" action runs it inline instead (it was
  already fully backgrounded before this change).
- Fixed "Missing X-Content-Type-Options" firing on every image/font/media/archive response once
  those started being header-analyzed at all (see the content-type/extension filter fix above):
  the existing Sec-Fetch-Dest/URL-extension/MIME-aware relevance check for that finding only ran
  from the body-based analyze() overload, not the header-only one those responses actually use.
  Real disclosures (Server/X-Varnish-*/etc) on the same responses are unaffected, confirmed by
  test; nosniff still fires normally on genuine script/style responses.
- Fixed `ThrottledRequestSender`'s own direct-send fallback calls being unprotected: confirmed
  live that `api.http().sendRequest(...)` can itself throw an uncaught `NullPointerException`
  (Burp's own HTTP accessor transiently returning null), which previously killed whichever probe
  task happened to call it. Now routed through the same defensive catch-and-log shape as
  `SafeLogging`.
- Fixed the cache-key disclosure probe showing the wrong request/response as its default PoC:
  when more than one debug Pragma token disclosed something (a literal cache key from the first
  token, then also an unrelated Akamai extracted-values dump from a later one), the displayed
  evidence kept getting overwritten by whichever token happened to run last instead of staying on
  the first one that actually disclosed anything. Every exchange is still recorded and selectable
  as before; only which one is shown by default was wrong. Found and audited the same shape across
  every other active probe with a multi-attempt loop: `JwtActiveProbe` had the identical bug (and
  worse, no exchange selector to fall back on, an analyst could be shown the REJECTED bad-signature
  attempt as "proof" of a successful alg:none bypass a different request actually demonstrated),
  now fixed the same way. CORS, session-invalidation and the Google API key probe were already
  correct.
- Fixed a second, related instance of the same evidence-overwrite bug, found live on an actual
  cache-key disclosure (evidence text correctly referenced the leaked key from a busted/Pragma
  request, but the displayed request/response was an unrelated clean exchange): the clean
  MISS-to-HIT confirmation pair unconditionally claimed the default displayed evidence whenever it
  also fired, even when the debug-Pragma battery just above it had already found the actual
  disclosure. Now only claims it when nothing more specific was already found; both exchanges are
  still recorded and selectable either way.

## 1.0.0 - unreleased

- Initial store-readiness baseline.
- Updated to Montoya API 2026.7 and added reproducible Gradle wrapper/CI builds.
- Added unit tests, bounded background queues and bounded JSON/browser payload parsing.
- Made the browser bridge disabled and authenticated by default, versioned its API and restricted
  CORS to recognized browser-extension origins.
- Documented privacy, security, contribution and BApp review evidence.
