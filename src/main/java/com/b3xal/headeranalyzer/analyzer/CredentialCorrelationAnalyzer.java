package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Bounded passive map of the locations in which the exact same credential appears. */
public final class CredentialCorrelationAnalyzer {
    private static final int MAX_CREDENTIALS = 4_000;
    private static final int MAX_LOCATIONS = 8_000;
    private final LinkedHashMap<String, State> states = new LinkedHashMap<>(128, .75f, true);
    private final LinkedHashMap<String, LocationState> locationStates = new LinkedHashMap<>(128, .75f, true);

    private static final class State {
        final Set<String> locations = new LinkedHashSet<>();
        boolean reported;
    }
    private static final class LocationState {
        String fingerprint;
        boolean rotationReported;
    }

    public synchronized void clear() { states.clear(); locationStates.clear(); }

    public synchronized List<HeaderFinding> observe(String url, Map<String, String> responseHeaders,
                                                     Map<String, String> requestHeaders,
                                                     CookiesAndAuthConfig config) {
        Map<String, Set<String>> observations = new LinkedHashMap<>();
        String host = host(url);
        String auth = header(requestHeaders, "Authorization");
        if (auth != null) {
            int space = auth.indexOf(' ');
            if (space > 0 && auth.substring(0, space).equalsIgnoreCase("Bearer"))
                add(observations, auth.substring(space + 1).trim(), host + " Authorization: Bearer");
        }
        for (String apiHeader : AuthHeaderAnalyzer.allApiKeyHeaders(config)) {
            String value = header(requestHeaders, apiHeader);
            if (value != null) add(observations, value.trim(), host + " request header " + apiHeader);
        }
        observeCookies(observations, header(requestHeaders, "Cookie"), host + " Cookie", config, false);
        observeCookies(observations, header(responseHeaders, "Set-Cookie"), host + " Set-Cookie", config, true);
        observeQuery(observations, url, host, config);

        List<HeaderFinding> findings = new ArrayList<>();
        observeRotations(observations, findings);
        for (Map.Entry<String, Set<String>> entry : observations.entrySet()) {
            String token = entry.getKey();
            String fingerprint = fingerprint(token);
            State state = states.computeIfAbsent(fingerprint, ignored -> new State());
            state.locations.addAll(entry.getValue());
            if (state.locations.size() >= 2 && !state.reported) {
                state.reported = true;
                String locations = String.join("; ", state.locations);
                findings.add(new HeaderFinding(
                        "Same authentication credential observed in multiple locations",
                        "Authentication correlation", token,
                        "The exact same credential value was passively observed in more than one transport or " +
                        "storage location. This is a correlation/inventory signal, not a vulnerability by itself; " +
                        "verify whether duplicate exposure is intentional and prefer one well-protected mechanism.",
                        "SHA-256 fingerprint " + fingerprint.substring(0, 16) + "…; locations: " + locations,
                        Severity.INFORMATION, Confidence.CERTAIN, HeaderFinding.Category.AUTH));
            }
        }
        trim();
        return findings;
    }

    private static void observeCookies(Map<String, Set<String>> out, String header, String source,
                                       CookiesAndAuthConfig config, boolean setCookie) {
        if (header == null) return;
        String[] items = setCookie ? header.split("\\n") : header.split(";");
        for (String item : items) {
            String first = setCookie ? item.split(";", 2)[0] : item;
            int eq = first.indexOf('=');
            if (eq <= 0) continue;
            String name = first.substring(0, eq).trim();
            String value = first.substring(eq + 1).trim();
            List<StructuredCookieJwtAnalyzer.ExtractedJwt> jwts = StructuredCookieJwtAnalyzer.extract(value);
            for (var jwt : jwts) add(out, jwt.token(), source + " " + name + " " + String.join(",", jwt.paths()));
            if (jwts.isEmpty() && CookieAnalyzer.nameLooksSensitive(name, config) && value.length() >= 8)
                add(out, value, source + " " + name);
        }
    }

    private static void observeQuery(Map<String, Set<String>> out, String url, String host,
                                     CookiesAndAuthConfig config) {
        try {
            String query = URI.create(url).getRawQuery();
            if (query == null) return;
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) continue;
                String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                boolean configured = config.extraQueryTokenParams.stream().anyMatch(k -> k.equalsIgnoreCase(key));
                String lower = key.toLowerCase(Locale.ROOT);
                if (configured || lower.matches(".*(token|api[_-]?key|session|jwt|secret).*"))
                    add(out, value, host + " URL query " + key);
                if (JwtAnalyzer.looksLikeJwt(value)) add(out, value, host + " URL query " + key);
            }
        } catch (RuntimeException ignored) { }
    }

    private static void add(Map<String, Set<String>> out, String value, String location) {
        if (value == null || value.isBlank()) return;
        out.computeIfAbsent(value, ignored -> new LinkedHashSet<>()).add(location);
    }

    private void observeRotations(Map<String, Set<String>> observations, List<HeaderFinding> findings) {
        for (Map.Entry<String, Set<String>> entry : observations.entrySet()) {
            String current = entry.getKey();
            String currentFingerprint = fingerprint(current);
            for (String location : entry.getValue()) {
                LocationState state = locationStates.computeIfAbsent(location, ignored -> new LocationState());
                if (state.fingerprint != null && !state.fingerprint.equals(currentFingerprint)
                        && !state.rotationReported) {
                    state.rotationReported = true;
                    findings.add(new HeaderFinding(
                            "Authentication mechanism value changed during capture",
                            "Authentication correlation", current,
                            "The credential carried by the same authentication location changed during this " +
                            "capture. Rotation is normally healthy and is not a vulnerability by itself; this " +
                            "timeline signal helps correlate login, refresh and logout transitions. A value " +
                            "change alone does not establish any server-side invalidation state.",
                            "Location: " + location + "; previous SHA-256: " + state.fingerprint.substring(0, 16) +
                                    "…; current SHA-256: " + currentFingerprint.substring(0, 16) + "…",
                            Severity.INFORMATION, Confidence.CERTAIN, HeaderFinding.Category.AUTH));
                }
                state.fingerprint = currentFingerprint;
            }
        }
    }

    private static String header(Map<String, String> headers, String name) {
        if (headers == null) return null;
        for (var entry : headers.entrySet()) if (entry.getKey().equalsIgnoreCase(name)) return entry.getValue();
        return null;
    }

    private static String fingerprint(String value) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) { throw new IllegalStateException(impossible); }
    }

    private static String host(String url) {
        try {
            String host = URI.create(url).getHost();
            return host == null || host.isBlank() ? "(unknown host)" : host.toLowerCase(Locale.ROOT);
        } catch (RuntimeException ignored) {
            return "(unknown host)";
        }
    }

    private void trim() {
        while (states.size() > MAX_CREDENTIALS) {
            var iterator = states.entrySet().iterator(); iterator.next(); iterator.remove();
        }
        while (locationStates.size() > MAX_LOCATIONS) {
            var iterator = locationStates.entrySet().iterator(); iterator.next(); iterator.remove();
        }
    }
}
