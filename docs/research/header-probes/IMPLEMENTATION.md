# Header influence probes: implementation

Updated on 8 September 2026 in Quimera Burp. The earlier design is kept in `PLAN.md`; this document describes the available behavior, not the plan's future expansions.

## Findings

- **Request header value reflected: name — Info.** Two independent canaries appear in the same place in the response and do not appear in four clean controls. It can be a response body or header. It does not assert XSS.
- **Request header controls response: name — Info.** The status, headers or body change reproducibly with the probed header and return to the initial state in controls. It does not require a reflected canary. An ordinary formatting change is also informational influence.
- **Header-triggered disclosure: input → output.** A known disclosure header appears or changes only with the probed input. The classification of the existing cache-diagnostic rules is preserved; additional metadata without demonstrated impact stays at Info.

Reflection and response control use the ACTIVE category. Disclosure uses INFORMATION_DISCLOSURE. They are shown in Quimera and published in native Issues with evidence; no unconfirmed difference is published as a confirmed finding. Findings are published as they are confirmed, without waiting for the end of the catalogue.

## Independent work and cost

`Quimera-HeaderInfluence` has **one worker and a queue of 128 jobs**, independent of Leaks, CORS, cache, JWT and Google. The engine also serializes retests with the automatic tests, avoiding two simultaneous runs of the module.

Settings expose a toggle and interval. Budgets saved by earlier versions are no longer read nor limit execution. Initial values:

| Limit | Value |
|---|---|
| Interval between module requests | 333 ms (approx. 3 requests/s); configurable minimum 250 ms |
| Requests per context/origin | No quota; the full eligible catalogue is traversed |
| Headers mutated per request | One, either existing or new |
| Findings per job | No cutoff by count; incremental publishing |
| Analyzed body | Up to 512 KiB, also after decompression |

Pauses on 429/503 and transport failures are kept: the worker waits and
retries **the same request**, preserving its position and values. It does not restart
the catalogue after a pause. A numeric `Retry-After` is capped at five minutes;
non-numeric values use 30 seconds. Three consecutive transport failures introduce
a 30-second pause before retrying. If the service still does not recover,
the job keeps waiting until it recovers or is cancelled.

Disabling the module cancels new automatic requests; unloading the extension also cancels retests; a
request inside `sendRequest` depends on Burp's timeouts. A scope change is
also checked after waiting. Status and progress are updated during
the job and written to Output every 50 candidates, when waiting and when finishing.
The count of tested candidates means attempted: an error or unreadable body
is not equivalent to the absence of influence.

The cutoffs of 64 requests, per-origin quota, 12 findings and 8 MiB
accumulated per job are removed. The automatic path delivers each result to the
Logger/Issues upon confirmation; the engine does not retain a list with all results of
the job. The queue is still 128 contexts and deduplicates observed contexts: traversing
the full catalogue of one context does not mean re-scanning every identical
repetition of the traffic. A full queue releases the key to allow its scheduling
if the context is observed again.

The pace corresponds to this module; it does not change other existing batteries.

## Catalogue and sources

Included are **216 typed recipes, with 132 names**, and **1,073 per-name discovery candidates**. Removing overlaps, the corpus covers **1,155 distinct names**, plus custom headers observed in the target's requests.

Recipes have a per-row source and text, URL, host, IP, literal or template values. They cover MDN, Chromium/Chrome, Firefox, WebKit, Apache/nginx/framework forwarding, CDN, tracing and presentation protocols for htmx, Inertia, Turbo and Next.js. The CMS review includes WordPress, Drupal and Joomla: their authentication/CSRF headers are preserved in the request but not altered; relevant negotiation entries are included, without inventing CMS-specific debug names.

The additional corpus combines Param Miner and `known-http-header-db` at pinned revisions. The latter aggregates information from MDN/IANA and other sources; the importer uses its request/response directions to exclude known response fields. **A dictionary candidate is not an official header nor a verified vulnerability.** A harmless marker is sent to investigate whether it is accepted or reflected; sensitive and protocol rules are also excluded at runtime.

Present, debug and application/proxy families are prioritized; variants are alternated so the budget is not exhausted testing only `Accept` values. Untyped candidates are tested afterwards. No data is downloaded nor sources queried during the scan.

- [Sources and curation decisions](CATALOG-SOURCES.md).
- [Expansion, additional sources and audit from five perspectives](AUDIT-2026-09-07.md).
- Recipes: `src/main/resources/com/b3xal/headeranalyzer/header-influence-catalog.tsv`.
- Discovery: `src/main/resources/com/b3xal/headeranalyzer/header-influence-discovery.tsv`.
- Offline importer: `scripts/build-header-influence-discovery.py`.
- Licenses included in the JAR: `com/b3xal/headeranalyzer/licenses/`.

## Controls and evidence

The confirmation sequence is **control 0, control 1, value A, control 2, value B, control 3**. Documented literal values are repeated exactly; generated values use distinct canaries. Each candidate is sent separately from the start; groups are not discarded for lack of signal. All observed custom names that pass the exclusions are also tested, without the old 128 request-header cutoff.

All exchanges keep the captured method, URL, authentication and context. The probe template adds a fixed internal marker and negotiates `Accept-Encoding: gzip, deflate, identity` identically in controls and mutations. This allows common compressed responses to be analyzed without modifying this header between the compared probes. The clean template, including that negotiation, is kept for retest.

Response headers are preserved with multiplicity. The influence comparison omits common volatile headers, UUIDs and ISO timestamps; it requires all four controls to match under that normalization in the compared parts. If the body is dynamic or cannot be fully read in some observation, only status and headers are compared; a decoder limitation is not influence. Reflection is checked directly against the response content, not against a local representation of the request.

In the detail view the A exchange is opened and the **Probe evidence** selector lets you see the controls and B. The sent header and the marker are highlighted when available. Native Issues present the individual tests first. Retest reproduces the specific recipe; it does not re-run the whole catalogue nor replace verification with a passive analysis.

## Filters and coverage limits

- Only eligible GET/HEAD are re-run. Clearly destructive or logout paths/actions are skipped. These filters cannot identify every GET endpoint with side effects in an application.
- 4xx/5xx responses do not generate findings for this module. Some known error/WAF templates with a 200 status are also rejected. The filter does not prove the absence of a vulnerability on error pages.
- 3xx responses are examined without following destinations introduced by the marker. HEAD and bodyless responses are evaluated only by their headers.
- The module's own requests are excluded from both the handler and the passive scanner to avoid recursion. The module respects `Restrict to scope` when enabled and excludes traffic from other extensions as an automatic trigger.
- Gzip and deflate are decompressed with a limit, including chains of up to three encodings applied in reverse order. The declared charset is decoded strictly; malformed bytes leave the body unevaluated. If the server ignores the negotiation and returns Brotli, Zstandard or another unsupported format, the header checks are kept and the body is marked as unevaluated.
- The HTML classifier describes text, attribute, comment or script regions; it is not an exploitability parser. No JavaScript is executed, no CRLF or external callbacks are sent.
- The conservative comparison may miss changes on highly dynamic pages. The dictionary does not model all dependencies between headers: recipes that need several coordinated entries may not trigger.
- Cache poisoning and persistent storage are not confirmed. If a canary appears in controls, it is not published as a confirmed isolated reflection. A cache that hides the mutation can produce an absence of signal, not a "safe" result.
- The implemented disclosure is differential over recognized headers; it is not a universal secret detector across all body formats. The Leaks module remains separate.

## Validation

The clean build of 8 September 2026 passed **187 tests with no failures,
errors or skips**, including local Apache. Verified: the traversal of all
candidates beyond 512 requests, the absence of a per-origin quota, more
than 12 findings published during the traversal, and recovery from 429/503 and
transport errors while preserving the pending request.

The suite includes tests for existing/new reflection, response change without reflection, new and modified disclosure, markers present only in the request, dynamic IDs, persistence in controls, 4xx/5xx, WAF pages, full traversal beyond 512 requests, publishing of more than 12 findings during the scan, recovery from 429/503 and transport errors, cancellation during a pause, gzip and maximum sizes. It includes real HTTP requests to a local test server.

An engine test was also run against a local Apache with `mod_headers`, documented in the audit. No visual verification session inside Burp nor a sweep against external services has been performed. The local fixtures test the engine and the confirmation invariants; they do not prove that every catalogue variant works on every version of every vendor.
