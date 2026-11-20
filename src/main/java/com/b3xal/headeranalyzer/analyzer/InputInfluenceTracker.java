package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import com.b3xal.headeranalyzer.browser.BrowserPayload;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Short-lived, in-memory exact-value tracker for input-to-state/header propagation. It records
 * literal values rather than hashes because its job is to make a live assessment explainable.
 * Nothing in this class is persisted, logged or sent outside Burp. Passive matches document a
 * real observed propagation only; arbitrary control is established separately by the active
 * parameter influence probe.
 */
public final class InputInfluenceTracker {
    static final long WINDOW_MILLIS = Duration.ofMinutes(5).toMillis();
    static final int MAX_EVENTS = 2_000;
    static final int MAX_VALUE_LENGTH = 8_192;
    private static final int MIN_DISTINCT_VALUE_LENGTH = 8;
    private static final Set<String> LOW_SIGNAL_NAMES = Set.of(
            "state", "nonce", "csrf", "xsrf", "page", "limit", "offset", "sort", "lang", "locale");

    private enum Surface { URL_PARAMETER, BODY_PARAMETER, RESPONSE_HEADER, RESPONSE_COOKIE,
        BROWSER_COOKIE, LOCAL_STORAGE, SESSION_STORAGE }

    private record Event(String host, String origin, Surface surface, String name, String value, String location,
                         long observedAt) { }

    private final Deque<Event> events = new ArrayDeque<>();
    private final LongSupplier clock;

    public InputInfluenceTracker() { this(System::currentTimeMillis); }

    InputInfluenceTracker(LongSupplier clock) {
        this.clock = clock;
    }

    /** Observes real HTTP traffic after its response has been captured. */
    public synchronized List<HeaderFinding> observeHttp(HttpRequestResponse exchange) {
        if (exchange == null || exchange.request() == null || exchange.response() == null) return List.of();
        String host = host(exchange.request().url());
        if (host.isBlank()) return List.of();
        long now = clock.getAsLong();
        purge(now);
        List<HeaderFinding> findings = new ArrayList<>();
        // Record this request's parameters first, then match the response's Set-Cookie and other
        // headers against EVERY recent event for this host. This passively catches both the
        // same-response case (a parameter echoed straight into a new Set-Cookie) and the
        // cross-request case (a value supplied in an earlier step of a multi-step flow that is only
        // written into a cookie/header several requests later). Exact value plus the meaningful()
        // name/length gate keeps collisions out; deduplicate() collapses repeats.
        for (ParsedHttpParameter parameter : exchange.request().parameters()) {
            Surface source = parameter.type() == HttpParameterType.URL ? Surface.URL_PARAMETER
                    : parameter.type() == HttpParameterType.BODY ? Surface.BODY_PARAMETER : null;
            if (source == null || !trackable(parameter.name(), parameter.value())) continue;
            events.addLast(new Event(host, origin(exchange.request().url()), source, parameter.name(),
                    parameter.value(),
                    source == Surface.URL_PARAMETER ? "URL query parameter" : "request body parameter", now));
        }
        for (HttpHeader header : exchange.response().headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                CookieValue cookie = cookieValue(header.value());
                if (cookie != null) findings.addAll(matchSink(host, Surface.RESPONSE_COOKIE,
                        cookie.name, cookie.value, "Set-Cookie: " + cookie.name, now));
            } else {
                findings.addAll(matchSink(host, Surface.RESPONSE_HEADER, header.name(), header.value(),
                        "response header " + header.name(), now));
            }
        }
        return deduplicate(findings);
    }

    /** Correlates the browser extension's real cookies and Storage snapshot with recent inputs. */
    public synchronized List<HeaderFinding> observeBrowser(BrowserPayload payload) {
        if (payload == null) return List.of();
        String host = host(payload.origin);
        if (host.isBlank()) host = payload.host == null ? "" : payload.host.toLowerCase(Locale.ROOT);
        if (host.isBlank()) return List.of();
        long now = clock.getAsLong();
        purge(now);
        List<HeaderFinding> findings = new ArrayList<>();
        for (BrowserPayload.BrowserCookie cookie : payload.browserCookies) {
            findings.addAll(matchSink(host, Surface.BROWSER_COOKIE, cookie.name(), cookie.value(),
                    "browser cookie " + cookie.name(), now));
        }
        findings.addAll(matchStorage(host, payload.origin, payload.localStorage, Surface.LOCAL_STORAGE, "localStorage", now));
        findings.addAll(matchStorage(host, payload.origin, payload.sessionStorage, Surface.SESSION_STORAGE, "sessionStorage", now));
        return deduplicate(findings);
    }

    public synchronized void clear() { events.clear(); }

    private List<HeaderFinding> matchStorage(String host, String origin, Map<String, String> storage, Surface surface,
                                              String label, long now) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (storage == null) return findings;
        for (Map.Entry<String, String> entry : storage.entrySet()) {
            if (!trackable(entry.getKey(), entry.getValue())) continue;
            for (Event source : events) {
                if (source.host.equals(host) && source.origin.equals(origin)) {
                    findings.addAll(match(source, surface, entry.getKey(), entry.getValue(),
                            label + "." + entry.getKey(), now));
                }
            }
        }
        return findings;
    }

    private List<HeaderFinding> matchSink(String host, Surface sink, String name, String value,
                                          String location, long now) {
        if (!trackable(name, value)) return List.of();
        List<HeaderFinding> findings = new ArrayList<>();
        for (Event source : events) if (source.host.equals(host)) {
            findings.addAll(match(source, sink, name, value, location, now));
        }
        return findings;
    }

    private List<HeaderFinding> match(Event source, Surface sink, String sinkName, String sinkValue,
                                      String sinkLocation, long now) {
        if (source.value == null || !source.value.equals(sinkValue)) return List.of();
        if (!meaningful(source, sinkName, sinkValue)) return List.of();
        String sourceLabel = source.location + " '" + source.name + "'";
        String title = switch (sink) {
            case RESPONSE_HEADER -> "Request parameter value propagated to response header";
            case RESPONSE_COOKIE, BROWSER_COOKIE -> "Request parameter value propagated to cookie";
            case LOCAL_STORAGE, SESSION_STORAGE -> "Request parameter value propagated to browser Web Storage";
            default -> "Request parameter value propagated";
        };
        String risk = switch (sink) {
            case LOCAL_STORAGE -> " The browser extension confirmed the stored value; any script on this origin can read localStorage.";
            case SESSION_STORAGE -> " The browser extension confirmed the stored value; scripts in this browsing context can read sessionStorage.";
            default -> " This is an exact passive propagation observation, not proof that arbitrary values are accepted.";
        };
        String evidence = "Source: " + sourceLabel + " = " + source.value + "\n"
                + "Sink: " + sinkLocation + " = " + sinkValue + "\n"
                + "Observed within " + Math.max(0, now - source.observedAt) + " ms";
        return List.of(new HeaderFinding(title, "(Input influence)", source.value,
                "The complete value supplied in " + sourceLabel + " later appeared in " + sinkLocation + "."
                        + risk + " Use the active parameter influence probe to establish full arbitrary-value control.",
                evidence, Severity.INFORMATION,
                (sink == Surface.LOCAL_STORAGE || sink == Surface.SESSION_STORAGE)
                        ? Confidence.CERTAIN : Confidence.FIRM,
                HeaderFinding.Category.INFORMATION_DISCLOSURE));
    }

    private static boolean trackable(String name, String value) {
        return name != null && !name.isBlank() && value != null && !value.isBlank()
                && value.length() <= MAX_VALUE_LENGTH;
    }

    /** Exact short values are too collision-prone unless their source and destination names agree. */
    private static boolean meaningful(Event source, String sinkName, String value) {
        if (value.length() >= MIN_DISTINCT_VALUE_LENGTH) return true;
        String a = normalize(source.name), b = normalize(sinkName);
        return !LOW_SIGNAL_NAMES.contains(a) && a.equals(b) && value.length() >= 2;
    }

    private static String normalize(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private static CookieValue cookieValue(String line) {
        if (line == null) return null;
        int eq = line.indexOf('=');
        if (eq <= 0) return null;
        int semi = line.indexOf(';', eq + 1);
        String name = line.substring(0, eq).trim();
        String value = line.substring(eq + 1, semi < 0 ? line.length() : semi).trim();
        return name.isEmpty() ? null : new CookieValue(name, value);
    }

    private record CookieValue(String name, String value) { }

    private void purge(long now) {
        while (!events.isEmpty() && (now - events.peekFirst().observedAt > WINDOW_MILLIS
                || events.size() > MAX_EVENTS)) events.removeFirst();
    }

    private static String host(String raw) {
        try {
            String host = URI.create(raw).getHost();
            return host == null ? "" : host.toLowerCase(Locale.ROOT);
        } catch (Exception ignored) { return ""; }
    }

    private static String origin(String raw) {
        try {
            URI uri = URI.create(raw);
            if (uri.getScheme() == null || uri.getHost() == null) return "";
            int port = uri.getPort();
            return uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getHost().toLowerCase(Locale.ROOT)
                    + (port < 0 ? "" : ":" + port);
        } catch (Exception ignored) { return ""; }
    }

    private static List<HeaderFinding> deduplicate(List<HeaderFinding> findings) {
        Map<String, HeaderFinding> unique = new LinkedHashMap<>();
        for (HeaderFinding finding : findings) unique.putIfAbsent(finding.issueName + "\u0001" + finding.evidence, finding);
        return List.copyOf(unique.values());
    }
}
