package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.model.*;
import com.b3xal.headeranalyzer.util.JsonUtil;
import com.b3xal.headeranalyzer.util.SafeLogging;
import com.b3xal.headeranalyzer.util.ThrottledRequestSender;

import java.util.*;

/** Read-only validation of an exposed Google AIza key. One instance performs one bounded battery;
 * deduplication is owned by QuimeraHttpHandler so this class never sees the same key twice. */
public final class GoogleApiKeyProbe {
    public static final String MARKER_HEADER = "X-Quimera-Google-Key-Probe";
    public static final String PROBE_LABEL = "Google API key validation";
    private static final String REFERENCE =
            "https://developers.google.com/maps/api-security-best-practices";

    /** {@code minImageBytes}: image checks only (0 for JSON checks). Google's static image
     * endpoints, unlike the JSON ones, don't always return a clean error status: an invalid or
     * unauthorized key can still get a 200 OK image/* response (an error/placeholder graphic)
     * instead of an error body, so Content-Type alone can't tell a real rendered map from that.
     * A placeholder is near-flat/solid color with a short text string, which PNG-compresses to far
     * fewer bytes than a real map tile's road/label/texture detail at the same pixel dimensions, so
     * a minimum body size is used as a content-complexity proxy. Requested size bumped to 100x100
     * (still one flat-rate billed request either way) to widen that gap. Heuristic, not exact;
     * threshold picked conservatively and worth revisiting after a live test against a known-bad key. */
    private record Check(String name, String url, boolean image, int minImageBytes) {
        Check(String name, String url) { this(name, url, false, 0); }
    }
    private static final int MIN_MAP_IMAGE_BYTES = 3000;
    private static final List<Check> CHECKS = List.of(
            new Check("Geocoding", "https://maps.googleapis.com/maps/api/geocode/json?address=Madrid&key="),
            new Check("Directions", "https://maps.googleapis.com/maps/api/directions/json?origin=40.4168,-3.7038&destination=40.4200,-3.6900&key="),
            new Check("Distance Matrix", "https://maps.googleapis.com/maps/api/distancematrix/json?origins=40.4168,-3.7038&destinations=40.4200,-3.6900&key="),
            new Check("Elevation", "https://maps.googleapis.com/maps/api/elevation/json?locations=40.4168,-3.7038&key="),
            new Check("Time Zone", "https://maps.googleapis.com/maps/api/timezone/json?location=40.4168,-3.7038&timestamp=1704067200&key="),
            new Check("Places Autocomplete", "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Madrid&key="),
            new Check("Places Details", "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJgTwKgJcpQg0RaSKMYcHeNsQ&fields=name&key="),
            new Check("Places Nearby Search", "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=40.4168,-3.7038&radius=20&key="),
            new Check("Places Text Search", "https://maps.googleapis.com/maps/api/place/textsearch/json?query=museum%20in%20Madrid&key="),
            new Check("Places Query Autocomplete", "https://maps.googleapis.com/maps/api/place/queryautocomplete/json?input=museum%20Mad&key="),
            new Check("Roads Nearest", "https://roads.googleapis.com/v1/nearestRoads?points=40.4168,-3.7038&key="),
            new Check("Roads Snap to Roads", "https://roads.googleapis.com/v1/snapToRoads?path=40.4168,-3.7038|40.4170,-3.7030&key="),
            new Check("Static Maps", "https://maps.googleapis.com/maps/api/staticmap?center=40.4168,-3.7038&zoom=14&size=100x100&key=", true, MIN_MAP_IMAGE_BYTES),
            new Check("Street View Static", "https://maps.googleapis.com/maps/api/streetview?size=100x100&location=40.4168,-3.7038&key=", true, MIN_MAP_IMAGE_BYTES),
            new Check("Custom Search", "https://www.googleapis.com/customsearch/v1?cx=017576662512468239146:omuauf_lfve&q=security&key="),
            new Check("Generative Language models", "https://generativelanguage.googleapis.com/v1beta/models?key=")
    );

    private final MontoyaApi api;
    // See ActiveHeaderScanner's own field of the same type for why: routes this probe's
    // verification requests through Burp's project-configured resource pool instead of an
    // unthrottled direct send.
    private final ThrottledRequestSender sender;

    public GoogleApiKeyProbe(MontoyaApi api) {
        this.api = api;
        this.sender = new ThrottledRequestSender(api, "Quimera - Credential verification");
    }

    /** Called from {@code QuimeraHttpHandler.shutdown()} on extension unload/reload. */
    public void shutdown() {
        sender.shutdown();
    }

    private enum Verdict { ACCEPTED, REJECTED, INCONCLUSIVE }
    private record ProbeResult(Check check, HttpRequestResponse exchange, Verdict verdict,
                               String reason) {}

    public UrlAnalysisResult probe(String key, UrlAnalysisResult source, String sourceLocation,
                                   HttpRequestResponse sourceEvidence) {
        if (key == null || !key.matches("AIza[0-9A-Za-z_-]{35}")) return null;
        List<ProbeResult> results = new ArrayList<>();
        for (Check check : CHECKS) {
            try {
                HttpRequest request = HttpRequest.httpRequestFromUrl(check.url + key)
                        .withUpdatedHeader(MARKER_HEADER, "1")
                        .withUpdatedHeader("User-Agent", "Quimera Google API key probe");
                HttpRequestResponse rr = sender.send(request);
                results.add(classify(check, rr));
            } catch (Exception ex) {
                SafeLogging.error(api, "[Quimera] Google API key probe " + check.name + ": " + ex.getMessage());
                results.add(new ProbeResult(check, null, Verdict.INCONCLUSIVE,
                        "Request failed: " + ex.getMessage()));
            }
        }
        List<ProbeResult> accepted = results.stream()
                .filter(r -> r.verdict == Verdict.ACCEPTED).toList();

        String services = accepted.stream().map(r -> r.check.name).reduce((a, b) -> a + ", " + b).orElse("");
        String evidence = buildEvidence(source, sourceLocation, results);
        boolean vulnerable = !accepted.isEmpty();
        HeaderFinding finding = new HeaderFinding(
                vulnerable ? "PROBE VULNERABLE: Google API key externally usable"
                        : "PROBE SAFE/INCONCLUSIVE: Google API key validation",
                sourceLocation == null ? "(response body)" : sourceLocation,
                key,
                vulnerable
                        ? "The exposed Google API key was accepted from the tester's network by " + accepted.size() +
                            " read-only Google API endpoint(s): " + services + ". This demonstrates external " +
                            "usability and potential quota or billing abuse. It does not prove the key has no " +
                            "restrictions at all; restrict it to the intended applications and APIs."
                        : "Quimera completed its bounded read-only Google API validation battery. No endpoint " +
                            "produced a confirmed successful result, so this is validation evidence rather than " +
                            "a vulnerability. Review the per-service REJECTED/INCONCLUSIVE results below.",
                evidence,
                vulnerable ? Severity.MEDIUM : Severity.INFORMATION,
                vulnerable ? Confidence.FIRM : Confidence.CERTAIN,
                HeaderFinding.Category.AUTH, REFERENCE);
        UrlAnalysisResult out = new UrlAnalysisResult(source.url, source.host, source.path,
                List.of(finding), source.rawHeaders, source.techFindings);
        List<ProbeResult> exchanges = results.stream()
                .filter(r -> r.exchange != null && r.exchange.response() != null).toList();
        HttpRequestResponse representative = !accepted.isEmpty() ? accepted.get(0).exchange
                : exchanges.isEmpty() ? sourceEvidence : exchanges.get(0).exchange;
        if (representative != null) {
            out.rawRequest = representative.request().toString();
            out.rawResponse = representative.response() == null ? "" : representative.response().toString();
            out.method = representative.request().method();
            out.statusCode = representative.response() == null ? -1 : representative.response().statusCode();
            out.contentLength = representative.response() == null ? -1 : representative.response().body().length();
            out.originalRequest = representative.request();
            out.originalResponse = representative.response();
        }
        out.probeExchanges = exchanges.stream().map(ProbeResult::exchange).toList();
        out.probeExchangeLabels = exchanges.stream()
                .map(r -> r.check.name + " | " + r.verdict).toList();
        out.probeLabel = vulnerable ? "PROBE VULNERABLE: Google API key"
                : "Google API key probe: no confirmed exploitation";
        return out;
    }

    private static ProbeResult classify(Check check, HttpRequestResponse rr) {
        if (rr == null || rr.response() == null || rr.response().statusCode() < 200
                || rr.response().statusCode() >= 300) {
            String reason = rr == null || rr.response() == null ? "No HTTP response"
                    : "HTTP " + rr.response().statusCode();
            return new ProbeResult(check, rr, Verdict.REJECTED, reason);
        }
        String contentType = rr.response().headerValue("Content-Type");
        if (check.image) {
            boolean imageType = contentType != null && contentType.toLowerCase(Locale.ROOT).startsWith("image/");
            int bytes = rr.response().body().length();
            Verdict verdict = imageType && bytes >= check.minImageBytes ? Verdict.ACCEPTED : Verdict.REJECTED;
            return new ProbeResult(check, rr, verdict,
                    "HTTP " + rr.response().statusCode() + ", " + (contentType == null ? "unknown type" : contentType)
                            + ", " + bytes + " response bytes");
        }
        String body = rr.response().bodyToString();
        if (body == null || body.isBlank())
            return new ProbeResult(check, rr, Verdict.INCONCLUSIVE, "HTTP 2xx with an empty response body");
        try {
            Object parsed = JsonUtil.parse(body);
            if (parsed instanceof Map<?,?> map) {
                if (map.containsKey("error"))
                    return new ProbeResult(check, rr, Verdict.REJECTED, "Google returned an error envelope");
                Object status = map.get("status");
                if (status != null) {
                    boolean ok = status.equals("OK") || status.equals("ZERO_RESULTS");
                    return new ProbeResult(check, rr, ok ? Verdict.ACCEPTED : Verdict.REJECTED,
                            "Google status: " + status);
                }
                return new ProbeResult(check, rr, Verdict.ACCEPTED,
                        "HTTP 2xx JSON without a Google error envelope");
            }
        } catch (RuntimeException ignored) { }
        return new ProbeResult(check, rr, Verdict.INCONCLUSIVE,
                "HTTP 2xx response could not be classified as Google success JSON");
    }

    private static String buildEvidence(UrlAnalysisResult source, String sourceLocation,
                                        List<ProbeResult> results) {
        long acceptedCount = results.stream().filter(r -> r.verdict == Verdict.ACCEPTED).count();
        StringBuilder out = new StringBuilder();
        out.append("VALIDATION RESULT\n")
                .append(acceptedCount > 0
                        ? "Google accepted the exposed key from the tester's network on " + acceptedCount + " service(s)."
                        : "No tested service returned a confirmed successful result.")
                .append("\n\n")
                .append("SOURCE\nLocation: ").append(sourceLocation == null ? "response body" : sourceLocation)
                .append("\nOriginal URL: ").append(source.url).append("\n\n")
                .append("PROBE SUMMARY\n");
        for (ProbeResult result : results) {
            out.append(result.verdict).append(" | ").append(result.check.name)
                    .append(" | ").append(result.reason).append('\n');
        }
        for (ProbeResult result : results) {
            if (result.verdict != Verdict.ACCEPTED || result.exchange == null) continue;
            String url = result.exchange.request().url();
            out.append("\nREPRODUCTION: ").append(result.check.name).append("\n")
                    .append("curl --silent --show-error '").append(url.replace("'", "'\\''")).append("'\n\n")
                    .append("RESPONSE\nHTTP ").append(result.exchange.response().statusCode()).append('\n');
            String contentType = result.exchange.response().headerValue("Content-Type");
            if (contentType != null) out.append("Content-Type: ").append(contentType).append('\n');
            if (result.check.image) {
                out.append("Binary image body: ").append(result.exchange.response().body().length())
                        .append(" bytes (open the Response tab to inspect it).\n");
            } else {
                String body = result.exchange.response().bodyToString();
                out.append('\n').append(body.length() <= 1600 ? body : body.substring(0, 1600) + "\n[truncated]")
                        .append('\n');
            }
        }
        out.append("\nIMPACT\nA successful result, rather than REQUEST_DENIED or a restriction error, " +
                "demonstrates external usability and possible quota or billing consumption.");
        return out.toString();
    }
}
