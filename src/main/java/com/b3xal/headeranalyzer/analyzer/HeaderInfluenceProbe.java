package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.*;
import com.b3xal.headeranalyzer.util.SafeLogging;

import java.net.URI;
import java.util.*;
import java.util.function.Function;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

import static com.b3xal.headeranalyzer.analyzer.HeaderInfluenceCatalog.Candidate;

/** One serialized, paced background lane for the complete header catalogue. */
public final class HeaderInfluenceProbe {
    public static final String MARKER_HEADER = "X-Quimera-Header-Influence";
    public static final String LABEL_PREFIX = "Header influence probe: ";
    private static final Pattern ACTION_PATH = Pattern.compile(
            "(?i)(?:^|[/_.?&=-])(?:logout|signout|delete|remove|destroy|unsubscribe|purge)(?:$|[/_.?&=-])");
    private static final Set<String> DISCLOSURE_HEADERS = Set.of("server", "x-powered-by",
            "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-backend-server",
            "x-origin-server", "x-debug-token-link", "x-sourcefiles", "x-runtime", "x-served-by",
            "x-drupal-cache-contexts", "x-drupal-cache-tags", "x-drupal-cache-max-age",
            "x-wp-doingitwrong", "x-litemage-debug-cc", "x-litemage-debug-info",
            "x-litemage-debug-tag", "x-litemage-debug-vary",
            "surrogate-key", "surrogate-control");

    public record Coverage(int requests, int candidates, int tested, int suppressed,
                           int inconclusive, String state) {}
    private volatile Coverage lastCoverage = new Coverage(0, 0, 0, 0, 0, "not started");
    private final MontoyaApi api;
    private final QuimeraSettings settings;
    private final Function<HttpRequest, HttpRequestResponse> transport;
    private final LongSupplier clock;
    private final Sleeper sleeper;
    private volatile boolean closed;
    private long nextRequestAt;
    @FunctionalInterface interface Sleeper { void sleep(long millis) throws InterruptedException; }

    public HeaderInfluenceProbe(MontoyaApi api, QuimeraSettings settings) {
        this(api, settings, request -> api.http().sendRequest(request),
                () -> System.nanoTime() / 1_000_000, Thread::sleep);
    }

    /** Uses the supplied transport while retaining this probe's own catalogue pacing and
     * Retry-After handling. ActiveHeaderScanner supplies its shared paced sender here. */
    HeaderInfluenceProbe(MontoyaApi api, QuimeraSettings settings,
                         Function<HttpRequest, HttpRequestResponse> transport) {
        this(api, settings, transport, () -> System.nanoTime() / 1_000_000, Thread::sleep);
    }

    HeaderInfluenceProbe(MontoyaApi api, QuimeraSettings settings,
                         Function<HttpRequest, HttpRequestResponse> transport,
                         LongSupplier clock, Sleeper sleeper) {
        this.api = api;
        this.settings = settings;
        this.transport = transport;
        this.clock = clock;
        this.sleeper = sleeper;
    }

    public void shutdown() { closed = true; }
    public Coverage lastCoverage() { return lastCoverage; }

    public static boolean eligible(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null || rr.response() == null) return false;
        int status = rr.response().statusCode();
        return status >= 200 && status < 400 && status != 304 && eligibleRequest(rr.request());
    }

    private static boolean eligibleRequest(HttpRequest request) {
        if (request == null || (!"GET".equalsIgnoreCase(request.method())
                && !"HEAD".equalsIgnoreCase(request.method()))) return false;
        try {
            URI uri = URI.create(request.url());
            return ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                    && uri.getHost() != null && uri.getRawUserInfo() == null
                    && !ACTION_PATH.matcher((uri.getPath() == null ? "" : uri.getPath())
                        + (uri.getQuery() == null ? "" : "?" + uri.getQuery())).find();
        } catch (Exception ignored) { return false; }
    }

    public synchronized List<UrlAnalysisResult> probe(HttpRequestResponse baseline) {
        List<UrlAnalysisResult> results = new ArrayList<>();
        probe(baseline, results::add);
        return results;
    }

    /** Publish each confirmed result immediately instead of retaining a whole catalogue run. */
    public synchronized void probe(HttpRequestResponse baseline, Consumer<UrlAnalysisResult> onResult) {
        probe(baseline, onResult, ignored -> { });
    }

    /**
     * As {@link #probe(HttpRequestResponse, Consumer)}, while exposing every real server
     * response to the caller. The active transport bypasses Burp's passive HTTP handler, so the
     * caller uses this hook for response-only leak/disclosure analysis. Never let that secondary
     * analysis affect the probe's request pacing or confirmation logic.
     */
    public synchronized void probe(HttpRequestResponse baseline, Consumer<UrlAnalysisResult> onResult,
                                   Consumer<HttpRequestResponse> onResponse) {
        if (!eligible(baseline) || !settings.isHeaderInfluenceProbeEnabled() || closed) return;
        run(baseline.request(), HeaderInfluenceCatalog.candidates(baseline.request()), false, onResult, onResponse);
    }

    /** Replays the exact candidate recipe using the clean captured template. */
    public synchronized UrlAnalysisResult retest(String label, HttpRequest template) {
        if (label == null || !label.startsWith(LABEL_PREFIX) || !eligibleRequest(template) || closed) return null;
        List<Candidate> candidates = HeaderInfluenceCatalog.candidates(template).stream()
                .filter(c -> label(c).equals(label)).toList();
        if (candidates.isEmpty()) return null;
        List<UrlAnalysisResult> results = new ArrayList<>();
        run(template, candidates, true, results::add, ignored -> { });
        return results.isEmpty() ? null : results.get(0);
    }

    private void run(HttpRequest template, List<Candidate> candidates, boolean manual,
                     Consumer<UrlAnalysisResult> onResult, Consumer<HttpRequestResponse> onResponse) {
        Run run = new Run(template, candidates.size(), manual, onResponse);
        int found = 0;
        try {
            run.publishCoverage("running");
            Observation control0 = run.send(run.base);
            Observation control1 = run.send(run.base);
            if (!usable(control0) || !usable(control1)) {
                if (run.available()) run.state = "baseline not evaluable";
                return;
            }
            for (Candidate candidate : candidates) {
                if (!run.available()) break;
                if (settings.isHeaderSuppressed(candidate.name())) {
                    run.excluded++;
                    continue;
                }
                // Every candidate, including absent headers, gets an individual request.
                String markerA = marker();
                Observation first = run.send(run.base.withHeader(candidate.name(), candidate.value(markerA, false)));
                if (!run.available()) break;
                run.tested++;
                run.publishCoverage("running");
                if (!usable(first)) continue;
                boolean stable = control0.response.signature(null).equals(control1.response.signature(null));
                boolean signal = !first.response.signature(null).equals(control1.response.signature(null))
                        || first.response.contains(markerA);
                if (!stable) {
                    signal = first.response.contains(markerA)
                            || (control0.response.signature(null, false).equals(control1.response.signature(null, false))
                                && !first.response.signature(null, false).equals(control1.response.signature(null, false)))
                            || !disclosures(first.response, first.response, control0.response, control1.response,
                                "", "").isEmpty();
                }
                if (!signal) continue;
                String markerB = marker();
                Observation cleanMiddle = run.send(run.base);
                Observation second = run.send(run.base.withHeader(candidate.name(), candidate.value(markerB, true)));
                Observation cleanEnd = run.send(run.base);
                if (!usable(cleanMiddle) || !usable(second) || !usable(cleanEnd)) continue;
                List<HeaderFinding> findings = confirm(candidate, markerA, markerB,
                        control0, control1, first, cleanMiddle, second, cleanEnd);
                if (!findings.isEmpty()) {
                    onResult.accept(result(template, candidate, findings,
                            List.of(control0, control1, first, cleanMiddle, second, cleanEnd)));
                    found++;
                }
                control0 = cleanMiddle;
                control1 = cleanEnd;
            }
            if (run.available()) run.state = "completed selected catalogue; excluded=" + run.excluded;
        } finally {
            if (run.state.equals("running") && !run.available()) run.state = "cancelled";
            run.publishCoverage(run.state);
        }
    }

    private static boolean usable(Observation o) {
        return o != null && o.response.allowedStatus() && !o.response.errorPage();
    }

    private static String marker() { return UUID.randomUUID().toString().replace("-", ""); }
    private static String label(Candidate c) {
        return LABEL_PREFIX + c.name() + " / " + Integer.toUnsignedString(c.id().hashCode(), 36);
    }

    private static List<HeaderFinding> confirm(Candidate c, String markerA, String markerB,
                                             Observation c0, Observation c1, Observation a,
                                             Observation c2, Observation b, Observation c3) {
        List<HeaderFinding> findings = new ArrayList<>();
        List<HeaderInfluenceResponse> controls = List.of(c0.response, c1.response, c2.response, c3.response);
        boolean cleanMarkers = controls.stream().noneMatch(r -> r.contains(markerA) || r.contains(markerB));
        Map<String, String> aHits = a.response.reflections(markerA);
        Map<String, String> bHits = b.response.reflections(markerB);
        aHits.keySet().retainAll(bHits.keySet());
        if (cleanMarkers && !aHits.isEmpty()) {
            String evidence = "Changed request header: " + c.name() + "\nValue A: " + c.value(markerA, false)
                    + "\nValue B: " + c.value(markerB, true) + "\n";
            for (var hit : aHits.entrySet()) evidence += hit.getKey() + "\nA: " + hit.getValue()
                    + "\nB: " + bHits.get(hit.getKey()) + "\n";
            findings.add(new HeaderFinding("Request header value reflected: " + c.name(), c.name(),
                    c.value(markerA, false),
                    "Two independently generated values sent in this request header appeared in the same response sink. "
                    + "Neither marker appeared in four clean controls. This confirms response reflection, not XSS. "
                    + "Browser delivery, escaping and execution have not been established. "
                    + "HTML context labels are descriptive rather than an execution verdict.", evidence,
                    Severity.INFORMATION, Confidence.CERTAIN, HeaderFinding.Category.ACTIVE, c.source()));
        }
        // Decoder failures and size limits are observation limits, not response influence.
        // Compare bodies only when every observation has a complete decoded body.
        boolean compareBody = a.response.bodyComplete && b.response.bodyComplete
                && controls.stream().allMatch(r -> r.bodyComplete
                    && c0.response.signature(null).equals(r.signature(null)));
        String baseline = c0.response.signature(null, compareBody);
        boolean stableControls = controls.stream().allMatch(r -> baseline.equals(r.signature(null, compareBody)));
        String sigA = a.response.signature(c.value(markerA, false), compareBody);
        String sigB = b.response.signature(c.value(markerB, true), compareBody);
        if (findings.isEmpty() && stableControls && sigA.equals(sigB) && !sigA.equals(baseline)) {
            String changes = changes(c0.response, a.response);
            findings.add(new HeaderFinding("Request header controls response: " + c.name(), c.name(),
                    c.value(markerA, false),
                    "The response changed reproducibly with this request header and returned to baseline in clean "
                    + "controls. This is an informational input-influence finding; it does not prove XSS, an access "
                    + "control bypass, or cache poisoning. Dynamic timestamps/UUIDs and routine volatile headers "
                    + "are excluded from the comparison.",
                    "Request header: " + c.name() + "\nA: " + c.value(markerA, false) + "\nB: "
                    + c.value(markerB, true) + "\n" + changes,
                    Severity.INFORMATION, Confidence.CERTAIN, HeaderFinding.Category.ACTIVE, c.source()));
        }
        List<HeaderFinding> disclosed = disclosures(a.response, b.response, c0.response, c1.response,
                c.value(markerA, false), c.value(markerB, true));
        for (HeaderFinding f : disclosed) {
            String key = f.headerName.toLowerCase(Locale.ROOT);
            if (!Objects.equals(c0.response.headers.get(key), c2.response.headers.get(key))
                    || !Objects.equals(c0.response.headers.get(key), c3.response.headers.get(key))) continue;
            findings.add(new HeaderFinding("Header-triggered disclosure: " + c.name() + " → " + f.headerName,
                    f.headerName, f.headerValue,
                    "This response field was introduced or changed in both single-header probes, while four clean "
                    + "controls retained the original field value or absence. Trigger: " + c.name() + ". " + f.description,
                    "Trigger header: " + c.name() + "\n" + f.evidence, f.severity, Confidence.CERTAIN,
                    HeaderFinding.Category.INFORMATION_DISCLOSURE, f.referenceUrl));
        }
        return findings;
    }

    private static List<HeaderFinding> disclosures(HeaderInfluenceResponse a, HeaderInfluenceResponse b,
                                                   HeaderInfluenceResponse c0, HeaderInfluenceResponse c1,
                                                   String valueA, String valueB) {
        Map<String, String> newFields = new LinkedHashMap<>();
        a.headers.forEach((name, values) -> {
            if (Objects.equals(c0.headers.get(name), c1.headers.get(name))
                    && !Objects.equals(c0.headers.get(name), values) && b.headers.containsKey(name)) {
                String value = String.join("\n", values);
                String second = String.join("\n", b.headers.get(name));
                // Literal values we supplied are reflection, not information about the server.
                if ((!valueA.isEmpty() && (value.equals(valueA) || (valueA.length() >= 8 && value.contains(valueA))))
                        || (!valueB.isEmpty() && (second.equals(valueB) || (valueB.length() >= 8 && second.contains(valueB))))) return;
                if (value.equals(second) && !value.isBlank()) newFields.put(name, value);
            }
        });
        List<HeaderFinding> out = new ArrayList<>(ActiveHeaderScanner.cacheKeyDisclosureFindings(newFields));
        Set<String> handled = new HashSet<>();
        out.forEach(f -> handled.add(f.headerName.toLowerCase(Locale.ROOT)));
        newFields.forEach((name, value) -> {
            if (DISCLOSURE_HEADERS.contains(name) && !handled.contains(name)) {
                out.add(new HeaderFinding("Response metadata disclosed", name, value,
                        "Response metadata became visible. Its sensitivity depends on the actual data; a product "
                        + "name, timing value or identifier alone does not establish an exploitable vulnerability.",
                        name + ": " + value, Severity.INFORMATION, Confidence.CERTAIN,
                        HeaderFinding.Category.INFORMATION_DISCLOSURE,
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"));
            }
        });
        return out;
    }

    private static String changes(HeaderInfluenceResponse control, HeaderInfluenceResponse mutated) {
        StringBuilder out = new StringBuilder("Control HTTP ").append(control.status)
                .append("; probe HTTP ").append(mutated.status).append('\n');
        Set<String> names = new TreeSet<>(control.headers.keySet()); names.addAll(mutated.headers.keySet());
        for (String name : names) if (!Objects.equals(control.headers.get(name), mutated.headers.get(name))) {
            out.append(name).append(": ").append(control.headers.get(name)).append(" → ")
                    .append(mutated.headers.get(name)).append('\n');
            if (out.length() > 4096) break;
        }
        if (control.bodyComplete && mutated.bodyComplete && !control.body.equals(mutated.body)) {
            int index = 0;
            while (index < Math.min(control.body.length(), mutated.body.length())
                    && control.body.charAt(index) == mutated.body.charAt(index)) index++;
            out.append("Response body difference at decoded offset ").append(index).append("\nControl: ")
                    .append(HeaderInfluenceResponse.excerpt(control.body, Math.min(index, control.body.length())))
                    .append("\nProbe: ").append(HeaderInfluenceResponse.excerpt(mutated.body, Math.min(index, mutated.body.length())));
        }
        return out.toString();
    }

    private static UrlAnalysisResult result(HttpRequest template, Candidate c, List<HeaderFinding> findings,
                                            List<Observation> observations) {
        Observation baseline = observations.get(0);
        // The third exchange is the first independently-confirmed mutated request (value A).
        // It is the evidence for the finding, whereas baseline is only a control.  Keeping the
        // control as originalRequest made generic detail/report views open an unrelated clean
        // response (often highlighting a coincidental Last-Modified header) instead of the
        // request that actually demonstrated the influence.
        Observation evidence = observations.get(2);
        URI uri = URI.create(template.url());
        String path = uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
        UrlAnalysisResult out = new UrlAnalysisResult(template.url(), uri.getHost(), path, findings,
                evidence.response.flatHeaders());
        out.originalRequest = evidence.exchange.request();
        out.originalResponse = evidence.exchange.response();
        out.rawRequest = evidence.exchange.request().toString();
        out.rawResponse = evidence.exchange.response().toString();
        out.method = evidence.exchange.request().method(); out.statusCode = evidence.response.status;
        out.contentLength = evidence.exchange.response().body().length();
        out.probeLabel = label(c);
        out.probeExchanges = observations.stream().map(Observation::exchange).toList();
        out.probeExchangeLabels = List.of("Clean control 0", "Clean control 1", "Single-header value A: " + c.name(),
                "Clean control 2", "Single-header value B: " + c.name(), "Clean control 3");
        return out;
    }

    private record Observation(HttpRequestResponse exchange, HeaderInfluenceResponse response) {}
    private final class Run {
        final HttpRequest base;
        final int candidateCount;
        final boolean manual;
        final Consumer<HttpRequestResponse> onResponse;
        int sent, tested, suppressed, inconclusive, consecutiveFailures, excluded;
        String state = "running";
        Run(HttpRequest template, int candidateCount, boolean manual, Consumer<HttpRequestResponse> onResponse) {
            // Keep all controls/mutations on the same decodable representation. In particular,
            // a browser's br/zstd preference must not silently hide body reflections from us.
            this.base = template.withHeader(MARKER_HEADER, marker())
                    .withHeader("Accept-Encoding", "gzip, deflate, identity");
            this.candidateCount = candidateCount; this.manual = manual;
            this.onResponse = onResponse == null ? ignored -> { } : onResponse;
        }
        boolean available() {
            return !closed && !Thread.currentThread().isInterrupted()
                    && (manual || settings.isHeaderInfluenceProbeEnabled())
                    && state.equals("running");
        }
        Observation send(HttpRequest request) {
            while (available()) {
                Observation observation = sendOnce(request);
                if (!available()) return null;
                if (observation != null && observation.response.status != 429
                        && observation.response.status != 503) return observation;
                // Keep this exact request and catalogue position while waiting for recovery.
            }
            return null;
        }
        Observation sendOnce(HttpRequest request) {
            if (!available()) return null;
            try {
                if (api != null && settings.isRestrictToScope() && !api.scope().isInScope(request.url())) {
                    state = "cancelled: outside scope"; return null;
                }
                while (clock.getAsLong() < nextRequestAt) {
                    if (!available()) return null;
                    sleeper.sleep(Math.min(100, nextRequestAt - clock.getAsLong()));
                }
                if (!available()) return null;
                if (api != null && settings.isRestrictToScope() && !api.scope().isInScope(request.url())) {
                    state = "cancelled: outside scope"; return null;
                }
                sent++;
                nextRequestAt = clock.getAsLong() + settings.getHeaderInfluenceDelayMillis();
                HttpRequestResponse rr = transport.apply(request);
                // The active sender does not invoke Quimera's passive HTTP handler. Deliver the
                // actual server response here so response-only leak/disclosure analysis has the
                // same coverage, including intentionally provoked 4xx/5xx error pages.
                try { onResponse.accept(rr); } catch (RuntimeException ignored) { }
                HeaderInfluenceResponse response = HeaderInfluenceResponse.of(rr);
                if (response == null) { failed(); return null; }
                consecutiveFailures = 0;
                if (!response.allowedStatus() || response.errorPage()) suppressed++;
                if (!response.bodyComplete) inconclusive++;
                if (response.status == 429 || response.status == 503) {
                    long seconds = 30;
                    try { seconds = Math.max(1, Math.min(300, Long.parseLong(rr.response().headerValue("Retry-After")))); }
                    catch (RuntimeException ignored) { /* conservative fallback */ }
                    nextRequestAt = Math.max(nextRequestAt, clock.getAsLong() + seconds * 1000);
                    publishCoverage("waiting: rate limit or service unavailable");
                }
                return new Observation(rr, response);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt(); state = "cancelled"; return null;
            } catch (Exception ex) {
                failed();
                if (api != null) SafeLogging.error(api, "[Quimera] Header influence request failed: " + ex.getMessage());
                return null;
            }
        }
        void publishCoverage(String progress) {
            lastCoverage = new Coverage(sent, candidateCount, tested, suppressed, inconclusive, progress);
            // Coverage remains available to the UI/scheduler, but normal probe progress is not
            // written to Output. A catalogue run is expected background work; errors are logged
            // separately at their source and findings appear in their normal result surfaces.
        }
        private void failed() {
            inconclusive++;
            if (++consecutiveFailures >= 3) {
                nextRequestAt = Math.max(nextRequestAt, clock.getAsLong() + 30_000);
                publishCoverage("waiting: repeated transport failures");
            }
        }
    }
}
