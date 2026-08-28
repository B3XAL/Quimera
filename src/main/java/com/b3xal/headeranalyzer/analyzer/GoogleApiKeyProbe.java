package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.model.*;
import com.b3xal.headeranalyzer.util.JsonUtil;

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
    public GoogleApiKeyProbe(MontoyaApi api) { this.api = api; }

    public UrlAnalysisResult probe(String key, UrlAnalysisResult source, String sourceLocation,
                                   HttpRequestResponse sourceEvidence) {
        if (key == null || !key.matches("AIza[0-9A-Za-z_-]{35}")) return null;
        List<String> accepted = new ArrayList<>();
        for (Check check : CHECKS) {
            try {
                HttpRequest request = HttpRequest.httpRequestFromUrl(check.url + key)
                        .withUpdatedHeader(MARKER_HEADER, "1")
                        .withUpdatedHeader("User-Agent", "Quimera Google API key probe");
                HttpRequestResponse rr = api.http().sendRequest(request);
                if (accepted(check, rr)) accepted.add(check.name);
            } catch (Exception ex) {
                api.logging().logToError("[Quimera] Google API key probe " + check.name + ": " + ex.getMessage());
            }
        }
        if (accepted.isEmpty()) return null;

        String services = String.join(", ", accepted);
        HeaderFinding finding = new HeaderFinding(
                "Google API key accepted by external APIs",
                sourceLocation == null ? "(response body)" : sourceLocation,
                key,
                "The exposed Google API key was accepted from the tester's network by " + accepted.size() +
                        " read-only Google API endpoint(s): " + services + ". This demonstrates external " +
                        "usability and potential quota or billing abuse. It does not prove the key has no " +
                        "restrictions at all; restrict it to the intended applications and APIs.",
                "Accepted services: " + services,
                Severity.MEDIUM, Confidence.FIRM, HeaderFinding.Category.AUTH, REFERENCE);
        UrlAnalysisResult out = new UrlAnalysisResult(source.url, source.host, source.path,
                List.of(finding), source.rawHeaders, source.techFindings);
        out.rawRequest = source.rawRequest;
        out.rawResponse = source.rawResponse;
        out.method = source.method;
        out.statusCode = source.statusCode;
        out.contentLength = source.contentLength;
        out.originalRequest = sourceEvidence != null ? sourceEvidence.request() : source.originalRequest;
        out.originalResponse = sourceEvidence != null ? sourceEvidence.response() : source.originalResponse;
        out.probeLabel = PROBE_LABEL;
        return out;
    }

    private static boolean accepted(Check check, HttpRequestResponse rr) {
        if (rr == null || rr.response() == null || rr.response().statusCode() < 200
                || rr.response().statusCode() >= 300) return false;
        String contentType = rr.response().headerValue("Content-Type");
        if (check.image) return contentType != null
                && contentType.toLowerCase(Locale.ROOT).startsWith("image/")
                && rr.response().body().length() >= check.minImageBytes;
        String body = rr.response().bodyToString();
        if (body == null || body.isBlank()) return false;
        try {
            Object parsed = JsonUtil.parse(body);
            if (parsed instanceof Map<?,?> map) {
                if (map.containsKey("error")) return false;
                Object status = map.get("status");
                if (status != null) return status.equals("OK") || status.equals("ZERO_RESULTS");
                return true; // 2xx JSON without Google's error envelope (Roads/Search/models).
            }
        } catch (RuntimeException ignored) { }
        return false;
    }
}
