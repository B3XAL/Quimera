# Changelog

## 1.0.1 - unreleased

- Evidence navigation and report aggregation improvements across DetailPanel, CookiePanel and
  ReportPanel, including new domain-level disclosure inventory and per-URL analysis results.
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
  This gate, and the general auto-scan dedup, now always log why a URL was or wasn't probed
  (`cache-key probe completed/skipped`, `auto active scan: N probe(s)/skipped`) instead of being
  silent on every outcome, which previously made "ran and found nothing" indistinguishable from
  "never ran" in Output/Errors.
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

## 1.0.0 - unreleased

- Initial store-readiness baseline.
- Updated to Montoya API 2026.7 and added reproducible Gradle wrapper/CI builds.
- Added unit tests, bounded background queues and bounded JSON/browser payload parsing.
- Made the browser bridge disabled and authenticated by default, versioned its API and restricted
  CORS to recognized browser-extension origins.
- Documented privacy, security, contribution and BApp review evidence.
