package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/** Reviewed request recipes, augmented with the actual application's non-sensitive headers. */
final class HeaderInfluenceCatalog {
    enum Kind { TOKEN, URL, HOST, IP, INTEGER, BOOLEAN, LITERAL }
    record Candidate(String name, Kind kind, String seed, String family, String source) {
        String value(String marker, boolean second) {
            if (seed.contains("{marker}")) return seed.replace("{marker}", marker);
            return switch (kind) {
                case TOKEN -> marker;
                case URL -> "https://q" + marker + ".invalid/";
                case HOST -> "q" + marker + ".invalid";
                case IP -> second ? "192.0.2.182" : "192.0.2.181";
                case INTEGER -> second ? "82" : "81";
                case BOOLEAN -> second ? "false" : "true";
                case LITERAL -> seed;
            };
        }
        String id() { return name + "\t" + kind + "\t" + seed; }
    }

    private static final Pattern NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9a-z-]{1,128}");
    // These need protocol/authentication-specific tests, not arbitrary header influence probes.
    private static final Set<String> RESERVED = Set.of("host", "connection", "content-length",
            "transfer-encoding", "te", "trailer", "upgrade", "expect", "accept-encoding",
            "keep-alive", "proxy-connection", "http2-settings",
            "content-encoding", "content-type", "content-range", "range", "destination", "overwrite",
            "depth", "lock-token", "if", "max-forwards", "x-http-method-override", "x-method-override",
            "x-http-method", "next-action", "x-middleware-subrequest", "x-envoy-original-dst-host");
    private static final Pattern SENSITIVE = Pattern.compile(
            ".*(?:authorization|authenticate|cookie|token|nonce|secret|password|passwd|api[-_]?key|csrf|xsrf|signature|credential|client-cert|session|purge|invalidat|method[-_]?override).*",
            Pattern.CASE_INSENSITIVE);

    static boolean allowed(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        return NAME.matcher(n).matches() && !RESERVED.contains(n) && !SENSITIVE.matcher(n).matches()
                && !n.startsWith("x-quimera-");
    }

    private static final List<Candidate> REVIEWED = load("header-influence-catalog.tsv");
    private static final List<Candidate> DISCOVERY = load("header-influence-discovery.tsv");

    static List<Candidate> reviewed() { return REVIEWED; }
    static List<Candidate> discovery() { return DISCOVERY; }

    static List<Candidate> candidates(HttpRequest request) {
        LinkedHashMap<String, Candidate> result = new LinkedHashMap<>();
        Set<String> present = new HashSet<>();
        request.headers().forEach(h -> present.add(h.name().toLowerCase(Locale.ROOT)));
        for (Candidate c : REVIEWED) if (present.contains(c.name)) result.put(c.id(), c);
        request.headers().forEach(h -> {
            String n = h.name().toLowerCase(Locale.ROOT);
            if (allowed(n) && REVIEWED.stream().noneMatch(c -> c.name.equals(n))) {
                Candidate c = new Candidate(n, Kind.TOKEN, "", "observed",
                        "https://portswigger.net/burp/documentation/desktop/testing-workflow/analyzing/hidden-inputs");
                result.put(c.id(), c);
            }
        });
        for (Candidate c : REVIEWED) result.putIfAbsent(c.id(), c);
        Set<String> typedNames = new HashSet<>();
        result.values().forEach(c -> typedNames.add(c.name));
        for (Candidate c : DISCOVERY) if (!typedNames.contains(c.name)) result.putIfAbsent(c.id(), c);
        // Round-robin variants: six Accept values must not consume the whole small budget
        // before the first forwarded-host, debug or custom application header is reached.
        Map<String, List<Candidate>> byName = new LinkedHashMap<>();
        result.values().stream().sorted(Comparator.comparingInt(c -> priority(c, present)))
                .forEach(c -> byName.computeIfAbsent(c.name, ignored -> new ArrayList<>()).add(c));
        List<Candidate> ordered = new ArrayList<>();
        for (int variant = 0;; variant++) {
            boolean added = false;
            for (List<Candidate> values : byName.values()) if (variant < values.size()) {
                Candidate candidate = values.get(variant);
                if (!candidate.family.equals("discovery")) {
                    ordered.add(candidate); added = true;
                }
            }
            if (!added) break;
        }
        // Do not let thousands of untyped names starve documented value variants.
        result.values().stream().filter(c -> c.family.equals("discovery")).forEach(ordered::add);
        return List.copyOf(ordered);
    }

    private static int priority(Candidate c, Set<String> present) {
        if (present.contains(c.name)) return c.family.equals("observed") ? 0 : 1;
        if (c.family.equals("discovery")) return 6;
        if (c.family.contains("debug")) return 2;
        if (Set.of("proxy", "nginx", "rails", "htmx", "turbo", "nextjs").contains(c.family)) return 3;
        if (c.family.equals("http-browser")) return 5;
        return 4;
    }

    private static List<Candidate> load(String resource) {
        var stream = HeaderInfluenceCatalog.class.getResourceAsStream(
                "/com/b3xal/headeranalyzer/" + resource);
        if (stream == null) throw new IllegalStateException("Header influence catalogue is missing");
        LinkedHashMap<String, Candidate> entries = new LinkedHashMap<>();
        try (var reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            for (String line; (line = reader.readLine()) != null;) {
                if (line.isBlank() || line.startsWith("#") || line.startsWith("name\t")) continue;
                String[] fields = line.split("\t", -1);
                if (fields.length != 5) throw new IllegalArgumentException("Invalid catalogue row: " + line);
                String name = fields[0].toLowerCase(Locale.ROOT);
                Candidate c = new Candidate(name, Kind.valueOf(fields[1]), fields[2], fields[3], fields[4]);
                if (allowed(name) && !c.seed.contains("\r") && !c.seed.contains("\n")
                        && c.seed.length() <= 1024 && c.source.startsWith("https://")) entries.put(c.id(), c);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot load header influence catalogue", ex);
        }
        return List.copyOf(entries.values());
    }
}
