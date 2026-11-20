package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.*;
import com.b3xal.headeranalyzer.util.SafeLogging;

import java.net.URI;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongSupplier;

/**
 * Opt-in active probe (default off). Mutates one request cookie's value with a random marker and
 * checks, with the same {@code C0..C3 + A/B} causal confirmation as {@link HeaderInfluenceProbe},
 * whether that cookie is reflected into the response or reproducibly controls it.
 *
 * <p><b>Session safety is the design constraint, not an afterthought.</b> Only cookies that are
 * clearly application preference/state data are ever mutated: session/auth/CSRF/infrastructure
 * cookies, cookies whose value is credential-shaped, and {@code __Host-}/{@code __Secure-} prefixed
 * cookies are excluded (default-deny, see {@link #safeToMutate}). Every excluded cookie is sent
 * unchanged on every probe request, and each request is derived afresh from the original template
 * (never from a previously mutated request), so a valid session is never altered or restored
 * incorrectly. A single cookie is changed per request; all others keep their captured values.
 */
public final class CookieInfluenceProbe {
    public static final String MARKER_HEADER = "X-Quimera-Cookie-Influence";
    public static final String LABEL_PREFIX = "Cookie influence probe: ";
    private static final String REFLECTION_REF =
            "https://portswigger.net/web-security/cross-site-scripting/reflected";
    // Bound both the per-request traffic and the risk surface: most apps carry only a handful of
    // mutable preference cookies, and a long value is more likely to be opaque state than a flag.
    private static final int MAX_COOKIES = 8;
    private static final int MAX_VALUE_LEN = 256;

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

    public CookieInfluenceProbe(MontoyaApi api, QuimeraSettings settings) {
        this(api, settings, request -> api.http().sendRequest(request),
                () -> System.nanoTime() / 1_000_000, Thread::sleep);
    }

    CookieInfluenceProbe(MontoyaApi api, QuimeraSettings settings,
                         Function<HttpRequest, HttpRequestResponse> transport) {
        this(api, settings, transport, () -> System.nanoTime() / 1_000_000, Thread::sleep);
    }

    CookieInfluenceProbe(MontoyaApi api, QuimeraSettings settings,
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

    /** Same eligibility gate as header influence: in-scope GET/HEAD, non-error base response. */
    public static boolean eligible(HttpRequestResponse rr) {
        return HeaderInfluenceProbe.eligible(rr);
    }

    record CookieCandidate(String name, String value) {}

    /** Cookies this probe is permitted to mutate, derived from the request's own Cookie header. */
    static List<CookieCandidate> candidates(HttpRequest request, CookiesAndAuthConfig config) {
        if (request == null) return List.of();
        List<CookieCandidate> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (ParsedHttpParameter p : request.parameters(HttpParameterType.COOKIE)) {
            if (p.name() == null || p.value() == null) continue;
            if (!seen.add(p.name().toLowerCase(Locale.ROOT))) continue;
            if (!safeToMutate(p.name(), p.value(), config)) continue;
            out.add(new CookieCandidate(p.name(), p.value()));
            if (out.size() >= MAX_COOKIES) break;
        }
        return out;
    }

    /**
     * Default-deny: a cookie is mutable only when it is clearly application preference/state data.
     * Session/auth/CSRF/infrastructure cookies, {@code __Host-}/{@code __Secure-} prefixed cookies,
     * and credential-shaped values are all refused so the probe can never disturb a live session or
     * tamper with a security-scoped cookie.
     */
    static boolean safeToMutate(String name, String value, CookiesAndAuthConfig config) {
        if (name == null || name.isBlank() || value == null || value.isEmpty()) return false;
        String lower = name.toLowerCase(Locale.ROOT);
        // Session/auth material and the application's own tracking/infra cookies: never touch.
        // nameLooksSensitive already covers session/sid/auth/token/jwt/sso plus user keywords and
        // returns false for infra/tracking, so add the infra guard back explicitly (we must not
        // mutate load-balancer stickiness/WAF-state cookies either, even though they are not auth).
        if (CookieAnalyzer.nameLooksSensitive(name, config)) return false;
        if (CookieAnalyzer.isInfrastructureCookie(name)) return false;
        if (lower.contains("csrf") || lower.contains("xsrf") || lower.contains("antiforgery")
                || lower.contains("anti-forgery") || lower.contains("requestverificationtoken")
                || lower.contains("secret") || lower.contains("password") || lower.contains("passwd")
                || lower.contains("apikey") || lower.contains("api-key") || lower.contains("api_key")
                || lower.contains("credential") || lower.contains("signature") || lower.contains("nonce"))
            return false;
        // Cookie-prefix security scoping: changing these can defeat a browser integrity guarantee.
        if (lower.startsWith("__host-") || lower.startsWith("__secure-")) return false;
        // A benign-looking name can still hide a session token. Refuse credential-shaped values.
        if (value.length() > MAX_VALUE_LEN) return false;
        if (value.contains("eyJ")) return false; // JWT-shaped
        if (WebStorageAnalyzer.looksLikeOpaqueToken(value)) return false;
        return true;
    }

    public synchronized List<UrlAnalysisResult> probe(HttpRequestResponse baseline) {
        List<UrlAnalysisResult> results = new ArrayList<>();
        probe(baseline, results::add, ignored -> { });
        return results;
    }

    public synchronized void probe(HttpRequestResponse baseline, Consumer<UrlAnalysisResult> onResult) {
        probe(baseline, onResult, ignored -> { });
    }

    public synchronized void probe(HttpRequestResponse baseline, Consumer<UrlAnalysisResult> onResult,
                                   Consumer<HttpRequestResponse> onResponse) {
        if (!eligible(baseline) || !settings.isCookieInfluenceProbeEnabled() || closed) return;
        List<CookieCandidate> candidates = candidates(baseline.request(), settings.cookiesAndAuthConfig());
        if (candidates.isEmpty()) return;
        run(baseline.request(), candidates, false, onResult, onResponse);
    }

    /** Replays one cookie's recipe from the clean captured template (manual Retest). An explicit
     * Retest is an intentional one-off, so it runs even when the auto toggle is off; run()'s own
     * per-send scope check still applies. */
    public synchronized UrlAnalysisResult retest(String label, HttpRequest template) {
        if (label == null || !label.startsWith(LABEL_PREFIX) || template == null || closed) return null;
        List<CookieCandidate> candidates = candidates(template, settings.cookiesAndAuthConfig()).stream()
                .filter(c -> label(c).equals(label)).toList();
        if (candidates.isEmpty()) return null;
        List<UrlAnalysisResult> results = new ArrayList<>();
        run(template, candidates, true, results::add, ignored -> { });
        return results.isEmpty() ? null : results.get(0);
    }

    private void run(HttpRequest template, List<CookieCandidate> candidates, boolean manual,
                     Consumer<UrlAnalysisResult> onResult, Consumer<HttpRequestResponse> onResponse) {
        Run run = new Run(template, candidates.size(), manual, onResponse);
        try {
            run.publishCoverage("running");
            Observation control0 = run.send(run.base);
            Observation control1 = run.send(run.base);
            if (!usable(control0) || !usable(control1)) {
                if (run.available()) run.state = "baseline not evaluable";
                return;
            }
            for (CookieCandidate candidate : candidates) {
                if (!run.available()) break;
                String markerA = marker();
                Observation first = run.send(mutate(run.base, candidate.name(), markerA));
                if (!run.available()) break;
                run.tested++;
                run.publishCoverage("running");
                if (!usable(first)) continue;
                boolean signal = !first.response.signature(markerA).equals(control1.response.signature(markerA))
                        || first.response.contains(markerA);
                if (!signal) continue;
                String markerB = marker();
                Observation cleanMiddle = run.send(run.base);
                Observation second = run.send(mutate(run.base, candidate.name(), markerB));
                Observation cleanEnd = run.send(run.base);
                if (!usable(cleanMiddle) || !usable(second) || !usable(cleanEnd)) continue;
                List<HeaderFinding> findings = confirm(candidate, markerA, markerB,
                        control0, control1, first, cleanMiddle, second, cleanEnd);
                if (!findings.isEmpty())
                    onResult.accept(result(template, candidate, findings,
                            List.of(control0, control1, first, cleanMiddle, second, cleanEnd)));
                control0 = cleanMiddle;
                control1 = cleanEnd;
            }
            if (run.available()) run.state = "completed cookie probes";
        } finally {
            if (run.state.equals("running") && !run.available()) run.state = "cancelled";
            run.publishCoverage(run.state);
        }
    }

    /**
     * Replaces exactly one cookie's value by rewriting the Cookie header, preserving every other
     * cookie's name, value and order verbatim (session/auth cookies therefore travel unchanged).
     * The marker value is plain hex, so no cookie-octet escaping is needed. Done with header string
     * surgery rather than {@code HttpParameter.cookieParameter(...)} so the result is deterministic
     * and independent of Burp's cookie encoding. If the named cookie is absent the base is returned.
     */
    static HttpRequest mutate(HttpRequest base, String name, String value) {
        String original = base.headerValue("Cookie");
        if (original == null || original.isBlank()) return base;
        StringBuilder rebuilt = new StringBuilder();
        boolean replaced = false;
        for (String part : original.split(";")) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) continue;
            int eq = trimmed.indexOf('=');
            String cookieName = eq < 0 ? trimmed : trimmed.substring(0, eq).trim();
            if (rebuilt.length() > 0) rebuilt.append("; ");
            if (eq >= 0 && cookieName.equals(name)) {
                rebuilt.append(name).append('=').append(value);
                replaced = true;
            } else {
                rebuilt.append(trimmed);
            }
        }
        return replaced ? base.withHeader("Cookie", rebuilt.toString()) : base;
    }

    private static boolean usable(Observation o) {
        return o != null && o.response.allowedStatus() && !o.response.errorPage();
    }

    private static String marker() { return UUID.randomUUID().toString().replace("-", ""); }
    private static String label(CookieCandidate c) {
        return LABEL_PREFIX + c.name() + " / " + Integer.toUnsignedString(c.name().hashCode(), 36);
    }

    private static List<HeaderFinding> confirm(CookieCandidate c, String markerA, String markerB,
                                               Observation c0, Observation c1, Observation a,
                                               Observation c2, Observation b, Observation c3) {
        List<HeaderFinding> findings = new ArrayList<>();
        List<HeaderInfluenceResponse> controls = List.of(c0.response, c1.response, c2.response, c3.response);
        boolean cleanMarkers = controls.stream().noneMatch(r -> r.contains(markerA) || r.contains(markerB));
        Map<String, String> aHits = a.response.reflections(markerA);
        Map<String, String> bHits = b.response.reflections(markerB);
        aHits.keySet().retainAll(bHits.keySet());
        if (cleanMarkers && !aHits.isEmpty()) {
            StringBuilder evidence = new StringBuilder("Changed request cookie: " + c.name()
                    + "\nOriginal value: " + c.value() + "\nValue A: " + markerA + "\nValue B: " + markerB + "\n");
            for (var hit : aHits.entrySet())
                evidence.append(hit.getKey()).append("\nA: ").append(hit.getValue())
                        .append("\nB: ").append(bHits.get(hit.getKey())).append('\n');
            findings.add(new HeaderFinding("Request cookie value reflected: " + c.name(), "Cookie: " + c.name(),
                    markerA,
                    "Two independently generated values set in this non-session cookie appeared in the same "
                    + "response sink, and neither appeared in four clean controls. This confirms response "
                    + "reflection, not XSS: escaping, context and execution were not established, and a reflected "
                    + "cookie is self-contained unless an attacker can also set this cookie in a victim's browser "
                    + "(for example via a related-domain subdomain, response-header injection, or a document.cookie "
                    + "sink). HTML context labels are descriptive, not an execution verdict.",
                    evidence.toString(), Severity.INFORMATION, Confidence.CERTAIN,
                    HeaderFinding.Category.ACTIVE, REFLECTION_REF));
        }
        boolean compareBody = a.response.bodyComplete && b.response.bodyComplete
                && controls.stream().allMatch(r -> r.bodyComplete
                    && c0.response.signature(null).equals(r.signature(null)));
        String baseline = c0.response.signature(null, compareBody);
        boolean stableControls = controls.stream().allMatch(r -> baseline.equals(r.signature(null, compareBody)));
        String sigA = a.response.signature(markerA, compareBody);
        String sigB = b.response.signature(markerB, compareBody);
        if (findings.isEmpty() && stableControls && sigA.equals(sigB) && !sigA.equals(baseline)) {
            findings.add(new HeaderFinding("Request cookie controls response: " + c.name(), "Cookie: " + c.name(),
                    markerA,
                    "The response changed reproducibly with this non-session cookie's value and returned to "
                    + "baseline in clean controls. This is an informational input-influence finding (the cookie "
                    + "behaves like a hidden parameter, e.g. a language/theme/feature flag); it does not prove "
                    + "XSS, an access-control bypass, or cache poisoning. Dynamic timestamps/UUIDs and routine "
                    + "volatile headers are excluded from the comparison.",
                    "Request cookie: " + c.name() + "\nOriginal value: " + c.value() + "\nA: " + markerA
                    + "\nB: " + markerB + "\n" + changes(c0.response, a.response),
                    Severity.INFORMATION, Confidence.CERTAIN, HeaderFinding.Category.ACTIVE, REFLECTION_REF));
        }
        return findings;
    }

    private static String changes(HeaderInfluenceResponse control, HeaderInfluenceResponse mutated) {
        StringBuilder out = new StringBuilder("Control HTTP ").append(control.status)
                .append("; probe HTTP ").append(mutated.status).append('\n');
        Set<String> names = new TreeSet<>(control.headers.keySet()); names.addAll(mutated.headers.keySet());
        for (String name : names) if (!Objects.equals(control.headers.get(name), mutated.headers.get(name))) {
            out.append(name).append(": ").append(control.headers.get(name)).append(" -> ")
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

    private static UrlAnalysisResult result(HttpRequest template, CookieCandidate c, List<HeaderFinding> findings,
                                            List<Observation> observations) {
        Observation evidence = observations.get(2); // first confirmed mutated request (value A)
        URI uri = URI.create(template.url());
        String path = uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
        UrlAnalysisResult out = new UrlAnalysisResult(template.url(), uri.getHost(), path, findings,
                evidence.response.flatHeaders());
        out.originalRequest = evidence.exchange.request();
        out.originalResponse = evidence.exchange.response();
        out.rawRequest = evidence.exchange.request().toString();
        out.rawResponse = evidence.exchange.response().toString();
        out.method = evidence.exchange.request().method();
        out.statusCode = evidence.response.status;
        out.contentLength = evidence.exchange.response().body().length();
        out.probeLabel = label(c);
        out.probeExchanges = observations.stream().map(Observation::exchange).toList();
        out.probeExchangeLabels = List.of("Clean control 0", "Clean control 1", "Single-cookie value A: " + c.name(),
                "Clean control 2", "Single-cookie value B: " + c.name(), "Clean control 3");
        return out;
    }

    private record Observation(HttpRequestResponse exchange, HeaderInfluenceResponse response) {}
    private final class Run {
        final HttpRequest base;
        final int candidateCount;
        final boolean manual;
        final Consumer<HttpRequestResponse> onResponse;
        int sent, tested, suppressed, inconclusive, consecutiveFailures;
        String state = "running";
        Run(HttpRequest template, int candidateCount, boolean manual, Consumer<HttpRequestResponse> onResponse) {
            this.base = template.withHeader(MARKER_HEADER, marker())
                    .withHeader("Accept-Encoding", "gzip, deflate, identity");
            this.candidateCount = candidateCount; this.manual = manual;
            this.onResponse = onResponse == null ? ignored -> { } : onResponse;
        }
        boolean available() {
            return !closed && !Thread.currentThread().isInterrupted()
                    && (manual || settings.isCookieInfluenceProbeEnabled())
                    && state.equals("running");
        }
        Observation send(HttpRequest request) {
            while (available()) {
                Observation observation = sendOnce(request);
                if (!available()) return null;
                if (observation != null && observation.response.status != 429
                        && observation.response.status != 503) return observation;
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
                sent++;
                nextRequestAt = clock.getAsLong() + settings.getHeaderInfluenceDelayMillis();
                HttpRequestResponse rr = transport.apply(request);
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
                if (api != null) SafeLogging.error(api, "[Quimera] Cookie influence request failed: " + ex.getMessage());
                return null;
            }
        }
        void publishCoverage(String progress) {
            lastCoverage = new Coverage(sent, candidateCount, tested, suppressed, inconclusive, progress);
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
