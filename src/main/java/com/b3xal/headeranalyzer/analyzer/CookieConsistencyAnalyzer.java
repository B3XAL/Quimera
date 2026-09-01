package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Passive cross-response comparison of cookie security attributes and effective scope. */
public final class CookieConsistencyAnalyzer {

    private static final int MAX_IDENTITIES = 4_000;

    private record Snapshot(String host, String domain, String path, boolean secure, boolean httpOnly,
                            String sameSite, boolean persistent, String raw) {}

    private static final class State {
        Snapshot last;
        final Set<String> reported = new HashSet<>();
    }

    // Access ordered and synchronized through observe(), giving a simple bounded LRU without
    // retaining an unbounded number of cookies during a long Burp project.
    private final LinkedHashMap<String, State> states = new LinkedHashMap<>(128, 0.75f, true);

    public synchronized void clear() {
        states.clear();
    }

    public synchronized List<HeaderFinding> observe(String rawUrl, String setCookie,
                                                     CookiesAndAuthConfig config) {
        if (setCookie == null || setCookie.isBlank()) return List.of();
        URI uri;
        try {
            uri = URI.create(rawUrl);
        } catch (RuntimeException ex) {
            return List.of();
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) return List.of();
        host = host.toLowerCase(Locale.ROOT);
        String requestPath = uri.getRawPath();
        if (requestPath == null || requestPath.isEmpty()) requestPath = "/";

        List<HeaderFinding> findings = new ArrayList<>();
        for (String line : setCookie.split("\n")) {
            line = line.trim();
            if (line.isEmpty()) continue;
            String name = CookieAnalyzer.parseName(line);
            if (name.isBlank()) continue;
            List<String> attrs = CookieAnalyzer.parseAttrs(line);
            if (CookieAnalyzer.isBeingDeleted(line, attrs)) continue;
            if (config.cookieTrackingSkipEnabled && CookieAnalyzer.isKnownTrackingCookie(name, config)) continue;

            Snapshot current = snapshot(host, requestPath, line, attrs);
            // Key by issuing host and name so a later scope expansion/reduction remains comparable.
            String key = host + "|" + name.toLowerCase(Locale.ROOT);
            State state = states.computeIfAbsent(key, ignored -> new State());
            if (state.last != null) compare(name, state, state.last, current, findings);
            state.last = current;
            trim();
        }
        return findings;
    }

    private static Snapshot snapshot(String host, String requestPath, String raw, List<String> attrs) {
        String domain = attrValue(attrs, "domain=");
        if (domain == null || domain.isBlank()) domain = host;
        else {
            domain = domain.toLowerCase(Locale.ROOT);
            while (domain.startsWith(".")) domain = domain.substring(1);
        }
        String path = attrValue(attrs, "path=");
        if (path == null || path.isBlank() || !path.startsWith("/")) path = defaultPath(requestPath);
        String sameSite = attrValue(attrs, "samesite=");
        if (sameSite == null) sameSite = "(absent)";
        boolean persistent = attrs.stream().anyMatch(a -> a.startsWith("max-age=") || a.startsWith("expires="));
        return new Snapshot(host, domain, path,
                attrs.contains("secure"), attrs.contains("httponly"), sameSite, persistent, raw);
    }

    private static void compare(String name, State state, Snapshot old, Snapshot now,
                                List<HeaderFinding> findings) {
        compareBoolean(name, state, "Secure", old.secure, now.secure, old, now, findings);
        compareBoolean(name, state, "HttpOnly", old.httpOnly, now.httpOnly, old, now, findings);
        compareText(name, state, "SameSite", old.sameSite, now.sameSite, old, now, findings);

        if (!old.domain.equals(now.domain)) {
            boolean expanded = isParentDomain(now.domain, old.domain);
            if (expanded) {
                add(name, state, "Domain:" + old.domain + "->" + now.domain,
                        "Cookie Domain scope expanded between responses: " + name,
                        "Cookie '" + name + "' changed effective Domain from '" + old.domain + "' to '" +
                        now.domain + "'. The newer scope is broader and exposes the cookie to additional subdomains.",
                        Severity.LOW, old, now, findings);
            }
        }
        if (!old.path.equals(now.path)) {
            boolean expanded = pathContains(now.path, old.path) && !pathContains(old.path, now.path);
            if (expanded) {
                add(name, state, "Path:" + old.path + "->" + now.path,
                        "Cookie Path scope expanded between responses: " + name,
                        "Cookie '" + name + "' changed effective Path from '" + old.path + "' to '" +
                        now.path + "'. The newer path is broader; verify sharing across routes is intentional.",
                        Severity.LOW, old, now, findings);
            }
        }
    }

    private static void compareBoolean(String name, State state, String attribute, boolean oldValue,
                                       boolean newValue, Snapshot old, Snapshot now,
                                       List<HeaderFinding> findings) {
        if (oldValue == newValue || !oldValue || newValue) return;
        boolean downgrade = true;
        add(name, state, attribute + ":" + oldValue + "->" + newValue,
                "Cookie " + attribute + " is inconsistent between responses: " + name,
                "Cookie '" + name + "' was emitted both " + (oldValue ? "with" : "without") + " " +
                attribute + " and " + (newValue ? "with" : "without") + " it. " +
                (downgrade ? "The latest emission weakens the cookie's protection."
                           : "Clients can receive different security properties depending on the code path."),
                Severity.MEDIUM, old, now, findings);
    }

    private static void compareText(String name, State state, String attribute, String oldValue,
                                    String newValue, Snapshot old, Snapshot now,
                                    List<HeaderFinding> findings) {
        if (oldValue.equals(newValue) || sameSiteRank(newValue) >= sameSiteRank(oldValue)) return;
        add(name, state, attribute + ":" + oldValue + "->" + newValue,
                "Cookie " + attribute + " is inconsistent between responses: " + name,
                "Cookie '" + name + "' changed " + attribute + " from '" + oldValue + "' to '" +
                newValue + "'. Different application paths are issuing the same cookie with different " +
                "cross-site behavior.", Severity.LOW, old, now, findings);
    }

    private static int sameSiteRank(String value) {
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "strict" -> 3;
            case "lax" -> 2;
            case "(absent)" -> 1; // modern browsers generally apply a Lax-by-default variant
            case "none" -> 0;
            default -> 0;
        };
    }

    private static void add(String name, State state, String changeKey, String title, String description,
                            Severity severity, Snapshot old, Snapshot now,
                            List<HeaderFinding> findings) {
        // Treat A->B and B->A as the same inconsistency for deduplication. Keep the attribute
        // prefix separate: comparing "Secure:true" to "false" directly made the old reverse-key
        // calculation asymmetric and reported the same oscillation twice.
        String dedupe = canonicalChangeKey(changeKey);
        if (!state.reported.add(dedupe)) return;
        findings.add(new HeaderFinding(title, "Set-Cookie", now.raw, description,
                "Previous: Set-Cookie: " + old.raw + "\nCurrent: Set-Cookie: " + now.raw,
                severity, Confidence.CERTAIN, Category.COOKIE,
                "https://www.rfc-editor.org/rfc/rfc6265"));
    }

    private static String canonicalChangeKey(String changeKey) {
        int colon = changeKey.indexOf(':');
        int arrow = changeKey.indexOf("->", colon + 1);
        if (colon < 0 || arrow < 0) return changeKey;
        String prefix = changeKey.substring(0, colon + 1);
        String left = changeKey.substring(colon + 1, arrow);
        String right = changeKey.substring(arrow + 2);
        return left.compareTo(right) <= 0
                ? prefix + left + "<->" + right
                : prefix + right + "<->" + left;
    }

    private static String attrValue(List<String> attrs, String prefix) {
        for (String attr : attrs) if (attr.startsWith(prefix)) return attr.substring(prefix.length()).trim();
        return null;
    }

    static String defaultPath(String requestPath) {
        if (requestPath == null || requestPath.isEmpty() || requestPath.charAt(0) != '/') return "/";
        if (requestPath.equals("/")) return "/";
        int lastSlash = requestPath.lastIndexOf('/');
        return lastSlash <= 0 ? "/" : requestPath.substring(0, lastSlash);
    }

    private static boolean isParentDomain(String possibleParent, String child) {
        return !possibleParent.equals(child) && child.endsWith("." + possibleParent);
    }

    private static boolean pathContains(String parent, String child) {
        if (parent.equals("/")) return true;
        if (parent.equals(child)) return true;
        return child.startsWith(parent.endsWith("/") ? parent : parent + "/");
    }

    private void trim() {
        while (states.size() > MAX_IDENTITIES) {
            var iterator = states.entrySet().iterator();
            iterator.next();
            iterator.remove();
        }
    }
}
