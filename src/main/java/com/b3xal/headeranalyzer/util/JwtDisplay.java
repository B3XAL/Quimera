package com.b3xal.headeranalyzer.util;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Shared JWT decode/pretty-print logic. Used identically by {@code ui.DetailPanel}'s Advisory
 * pane (Quimera's own UI) and {@code scanner.IssueFormatting} (Burp's native Issues tab), so a
 * JWT-carrying finding reads the same way, decoded claims and real dates instead of a raw base64
 * wall, regardless of which view an analyst happens to be looking at.
 */
public final class JwtDisplay {

    private JwtDisplay() {}

    private static final DateTimeFormatter TS_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

    /** headerJson/payloadJson are pretty-printed JSON, either can be null if that segment failed
     * to decode (e.g. a forged alg:none token's empty signature doesn't affect header/payload,
     * but a genuinely malformed payload segment would leave payloadJson null while header still
     * decodes fine). timestampLines is empty (never null) when payloadJson has none of JWT's
     * standard epoch-second claims. */
    public record Decoded(String headerJson, String payloadJson, List<String> timestampLines) {}

    /** Null if value isn't JWT-shaped at all (3 dot-separated segments, header decodes to JSON
     * containing an 'alg' key, same shape check every JWT-recognizing class in this codebase
     * already uses) or its header couldn't be decoded either way. */
    public static Decoded decode(String value) {
        if (value == null || value.isBlank()) return null;
        String[] parts = value.trim().split("\\.", -1);
        if (parts.length != 3) return null;

        String headerJson;
        try {
            Object header = JsonUtil.parse(base64UrlDecode(parts[0]));
            if (!(header instanceof Map<?, ?> hm) || !hm.containsKey("alg")) return null;
            headerJson = JsonUtil.write(header);
        } catch (Exception ex) {
            return null;
        }

        Object payloadObj = null;
        String payloadJson = null;
        try {
            payloadObj = JsonUtil.parse(base64UrlDecode(parts[1]));
            payloadJson = JsonUtil.write(payloadObj);
        } catch (Exception ignored) {
            // Malformed/empty payload segment, header alone still stands.
        }

        return new Decoded(headerJson, payloadJson, timestampLines(payloadObj));
    }

    /** Renders JWT's standard epoch-second time claims (RFC 7519: exp/iat/nbf, plus OIDC's
     * auth_time) as their own line each, raw field value AND its converted UTC date together, exp
     * additionally gets "(expires in ...)"/"(expired ... ago)" relative to right now. Empty (never
     * null) if payload isn't a JSON object or has none of these four claims. */
    private static List<String> timestampLines(Object payloadObj) {
        List<String> lines = new ArrayList<>();
        if (!(payloadObj instanceof Map<?, ?> m)) return lines;
        for (String key : new String[]{"iat", "nbf", "auth_time", "exp"}) {
            Object v = m.get(key);
            if (!(v instanceof Number num)) continue;
            long epoch = num.longValue();
            String converted = TS_FORMAT.format(Instant.ofEpochSecond(epoch)) + " UTC";
            if (key.equals("exp")) {
                long diff = epoch - Instant.now().getEpochSecond();
                converted += diff >= 0 ? "  (expires in " + humanDuration(diff) + ")"
                                       : "  (expired " + humanDuration(-diff) + " ago)";
            }
            lines.add(key + ": " + epoch + "  ->  " + converted);
        }
        return lines;
    }

    private static String humanDuration(long seconds) {
        long h = seconds / 3600;
        long m = (seconds % 3600) / 60;
        return h > 0 ? h + "h " + m + "m" : m + "m";
    }

    /** Most findings build evidence as "&lt;location text&gt;: &lt;value&gt;" or "&lt;location&gt;
     * = &lt;value&gt;" (JwtAnalyzer, the browser-bridge analyzers, ...), value being exactly
     * headerValue. Strips that suffix off so "where this was found" can be shown as its own clean
     * line instead of bleeding into an unbroken wall of base64/JSON. Null if evidence doesn't
     * actually contain value as a suffix, that's not a bug, just nothing to split off here. */
    public static String locationPrefix(String evidence, String value) {
        if (evidence == null || value == null || value.isBlank()) return null;
        int idx = evidence.lastIndexOf(value);
        if (idx < 0) return null;
        String prefix = evidence.substring(0, idx).replaceAll("[:=\\s\\->]+$", "").trim();
        return prefix.isBlank() ? null : prefix;
    }

    /** Pretty-printed JSON if value is a raw JSON blob (not a JWT), null otherwise (either not
     * JSON-shaped, or shaped like it but failed to actually parse). */
    public static String prettyJsonOrNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
        try {
            return JsonUtil.write(JsonUtil.parse(trimmed));
        } catch (Exception ex) {
            return null;
        }
    }

    private static String base64UrlDecode(String segment) {
        String padded = segment;
        int rem = padded.length() % 4;
        if (rem == 2) padded += "==";
        else if (rem == 3) padded += "=";
        return new String(Base64.getUrlDecoder().decode(padded), StandardCharsets.UTF_8);
    }
}
