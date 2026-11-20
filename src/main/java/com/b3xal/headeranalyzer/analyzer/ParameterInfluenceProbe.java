package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Safe GET/HEAD-only active confirmation for URL parameter to response-header influence. It sends
 * two independent markers and four clean controls, so a finding means the complete marker value
 * reached a response header twice and did not merely coincide with dynamic response content.
 */
public final class ParameterInfluenceProbe {
    public static final String MARKER_HEADER = "X-Quimera-Parameter-Influence";
    public static final String LABEL_PREFIX = "Parameter influence probe: ";
    private static final Pattern ACTION_PATH = Pattern.compile(
            "(?i)(?:^|[/_.?&=-])(?:logout|signout|delete|remove|destroy|unsubscribe|purge)(?:$|[/_.?&=-])");
    private static final int MAX_CANDIDATES = 12;

    record Candidate(String name, int index) { }
    private final MontoyaApi api;
    private final QuimeraSettings settings;
    private final Function<HttpRequest, HttpRequestResponse> transport;
    private volatile boolean closed;

    public ParameterInfluenceProbe(MontoyaApi api, QuimeraSettings settings,
                                   Function<HttpRequest, HttpRequestResponse> transport) {
        this.api = api;
        this.settings = settings;
        this.transport = transport;
    }

    public void shutdown() { closed = true; }

    public static boolean eligible(HttpRequestResponse baseline) {
        if (baseline == null || baseline.request() == null || baseline.response() == null) return false;
        int status = baseline.response().statusCode();
        return status >= 200 && status < 400 && status != 304 && eligibleRequest(baseline.request());
    }

    static boolean eligibleRequest(HttpRequest request) {
        if (request == null || (!"GET".equalsIgnoreCase(request.method()) && !"HEAD".equalsIgnoreCase(request.method()))) return false;
        try {
            URI uri = URI.create(request.url());
            return uri.getHost() != null && uri.getRawQuery() != null && !uri.getRawQuery().isBlank()
                    && !ACTION_PATH.matcher((uri.getRawPath() == null ? "" : uri.getRawPath()) + "?" + uri.getRawQuery()).find();
        } catch (Exception ignored) { return false; }
    }

    public synchronized void probe(HttpRequestResponse baseline, Consumer<UrlAnalysisResult> onResult,
                                   Consumer<HttpRequestResponse> onResponse) {
        if (closed || !settings.isParameterInfluenceProbeEnabled() || !eligible(baseline)) return;
        for (Candidate candidate : candidates(baseline.request())) {
            if (closed || !settings.isParameterInfluenceProbeEnabled()) return;
            UrlAnalysisResult result = probeCandidate(baseline.request(), candidate, onResponse);
            if (result != null) onResult.accept(result);
        }
    }

    public synchronized UrlAnalysisResult retest(String label, HttpRequest template) {
        if (closed || label == null || !label.startsWith(LABEL_PREFIX) || !eligibleRequest(template)) return null;
        for (Candidate candidate : candidates(template)) if (label(candidate).equals(label))
            return probeCandidate(template, candidate, ignored -> { });
        return null;
    }

    private UrlAnalysisResult probeCandidate(HttpRequest template, Candidate candidate,
                                              Consumer<HttpRequestResponse> onResponse) {
        String markerA = marker(), markerB = marker();
        List<Observation> observations = new ArrayList<>();
        for (HttpRequest request : List.of(clean(template), clean(template), mutate(template, candidate, markerA),
                clean(template), mutate(template, candidate, markerB), clean(template))) {
            Observation observation = send(request, onResponse);
            if (!usable(observation)) return null;
            observations.add(observation);
        }
        List<HeaderFinding> findings = confirm(candidate, markerA, markerB, observations);
        return findings.isEmpty() ? null : result(template, candidate, findings, observations);
    }

    private HttpRequest clean(HttpRequest request) {
        return request.withHeader(MARKER_HEADER, marker()).withHeader("Accept-Encoding", "gzip, deflate, identity");
    }

    private HttpRequest mutate(HttpRequest request, Candidate candidate, String marker) {
        return clean(request).withPath(mutatedPath(request.path(), candidate, marker));
    }

    static List<Candidate> candidates(HttpRequest request) {
        if (request == null) return List.of();
        String query = request.query();
        if (query == null || query.isBlank()) return List.of();
        List<Candidate> out = new ArrayList<>();
        String[] fields = query.split("&", -1);
        for (int i = 0; i < fields.length; i++) {
            int eq = fields[i].indexOf('=');
            String name = (eq < 0 ? fields[i] : fields[i].substring(0, eq)).trim();
            if (!name.isEmpty() && name.length() <= 128) out.add(new Candidate(name, i));
            if (out.size() >= MAX_CANDIDATES) break;
        }
        return out;
    }

    static String mutatedPath(String path, Candidate candidate, String marker) {
        int question = path.indexOf('?');
        if (question < 0) return path;
        String[] fields = path.substring(question + 1).split("&", -1);
        if (candidate.index < 0 || candidate.index >= fields.length) return path;
        int eq = fields[candidate.index].indexOf('=');
        String rawName = eq < 0 ? fields[candidate.index] : fields[candidate.index].substring(0, eq);
        fields[candidate.index] = rawName + "=" + marker;
        return path.substring(0, question + 1) + String.join("&", fields);
    }

    static List<HeaderFinding> confirm(Candidate candidate, String markerA, String markerB,
                                       List<Observation> observations) {
        if (observations.size() != 6) return List.of();
        List<HeaderInfluenceResponse> controls = List.of(observations.get(0).response, observations.get(1).response,
                observations.get(3).response, observations.get(5).response);
        if (controls.stream().anyMatch(r -> r.contains(markerA) || r.contains(markerB))) return List.of();
        Map<String, String> hitsA = headerHits(observations.get(2).response, markerA);
        Map<String, String> hitsB = headerHits(observations.get(4).response, markerB);
        List<HeaderFinding> out = new ArrayList<>();
        for (Map.Entry<String, String> hit : hitsA.entrySet()) {
            String second = hitsB.get(hit.getKey());
            if (second == null) continue;
            boolean complete = hit.getValue().equals(markerA) && second.equals(markerB);
            String title = complete ? "URL parameter controls complete response header value"
                    : "URL parameter value reflected into response header";
            String evidence = "Parameter: " + candidate.name + "\nValue A: " + markerA + "\nValue B: " + markerB
                    + "\nResponse header: " + hit.getKey() + "\nA: " + hit.getValue() + "\nB: " + second;
            out.add(new HeaderFinding(title, hit.getKey(), markerA,
                    complete
                            ? "Two independently generated values supplied through this URL parameter became the complete value of the same response header, while four clean controls contained neither marker. This confirms arbitrary full-value response-header control."
                            : "Two independently generated values supplied through this URL parameter appeared in the same response-header value, while four clean controls contained neither marker. This confirms reflection into a response header, but the server adds other content.",
                    evidence, complete ? Severity.LOW : Severity.INFORMATION, Confidence.CERTAIN,
                    HeaderFinding.Category.ACTIVE));
        }
        return out;
    }

    private static Map<String, String> headerHits(HeaderInfluenceResponse response, String marker) {
        Map<String, String> hits = new LinkedHashMap<>();
        response.headers.forEach((name, values) -> values.stream().filter(v -> v.contains(marker))
                .findFirst().ifPresent(value -> hits.put(name, value)));
        return hits;
    }

    private Observation send(HttpRequest request, Consumer<HttpRequestResponse> onResponse) {
        try {
            if (api != null && settings.isRestrictToScope() && !api.scope().isInScope(request.url())) return null;
            HttpRequestResponse exchange = transport.apply(request);
            if (exchange != null) onResponse.accept(exchange);
            HeaderInfluenceResponse response = HeaderInfluenceResponse.of(exchange);
            return response == null ? null : new Observation(exchange, response);
        } catch (RuntimeException ignored) { return null; }
    }

    private static boolean usable(Observation observation) {
        return observation != null && observation.response.allowedStatus() && !observation.response.errorPage();
    }

    private static String marker() { return "qpi" + UUID.randomUUID().toString().replace("-", ""); }
    private static String label(Candidate candidate) {
        return LABEL_PREFIX + candidate.name + " / " + Integer.toUnsignedString(candidate.index, 36);
    }

    private static UrlAnalysisResult result(HttpRequest template, Candidate candidate, List<HeaderFinding> findings,
                                            List<Observation> observations) {
        Observation evidence = observations.get(2);
        URI uri = URI.create(template.url());
        String path = uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
        UrlAnalysisResult result = new UrlAnalysisResult(template.url(), uri.getHost(), path, findings,
                evidence.response.flatHeaders());
        result.originalRequest = evidence.exchange.request();
        result.originalResponse = evidence.exchange.response();
        result.rawRequest = evidence.exchange.request().toString();
        result.rawResponse = evidence.exchange.response().toString();
        result.method = evidence.exchange.request().method();
        result.statusCode = evidence.response.status;
        result.contentLength = evidence.exchange.response().body().length();
        result.probeLabel = label(candidate);
        result.probeExchanges = observations.stream().map(Observation::exchange).toList();
        result.probeExchangeLabels = List.of("Clean control 0", "Clean control 1", "Parameter value A: " + candidate.name,
                "Clean control 2", "Parameter value B: " + candidate.name, "Clean control 3");
        return result;
    }

    static record Observation(HttpRequestResponse exchange, HeaderInfluenceResponse response) { }
}
