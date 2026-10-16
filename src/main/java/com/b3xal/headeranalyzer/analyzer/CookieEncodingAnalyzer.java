package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.util.JsonUtil;

import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

/** Detects transparent transport encodings in cookie values. This is an inventory signal, not a
 * claim that encoding itself is encryption or a vulnerability. */
final class CookieEncodingAnalyzer {
    private CookieEncodingAnalyzer() {}
    private static final int MAX_INPUT = 65_536;
    private static final int MAX_DECODED = 65_536;
    private static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9+/_-]{16,}={0,2}");
    private static final Pattern HEX = Pattern.compile("(?i)[0-9a-f]{16,}");
    private static final Pattern FORM = Pattern.compile("[A-Za-z][A-Za-z0-9_.-]{0,63}=[^&=]+(?:&[A-Za-z][A-Za-z0-9_.-]{0,63}=[^&=]+)*");
    private static final Pattern SENSITIVE_FIELD = Pattern.compile("(?i).*(?:access[_-]?token|refresh[_-]?token|id[_-]?token|auth(?:orization)?|bearer|api[_-]?key|secret|password|credential|session|ssn|national[_-]?id|credit[_-]?card).*");

    static List<HeaderFinding> analyze(String name, String raw, String sourceHeader) {
        if (raw == null || raw.isBlank() || raw.length() > MAX_INPUT) return List.of();
        String value = stripQuotes(raw.trim());
        List<HeaderFinding> findings = new ArrayList<>();
        String url = decodeUrl(value);
        if (url != null && actionable(url)) findings.add(f(name, raw, sourceHeader, "URL percent-encoded", url));
        if (BASE64.matcher(value).matches()) {
            String standard = decodeBase64(value, false);
            if (standard != null && actionable(standard)) findings.add(f(name, raw, sourceHeader, "Base64", standard));
            String urlSafe = decodeBase64(value, true);
            if (urlSafe != null && !urlSafe.equals(standard) && actionable(urlSafe))
                findings.add(f(name, raw, sourceHeader, "Base64URL", urlSafe));
        }
        if (HEX.matcher(value).matches() && value.length() % 2 == 0) {
            String decoded = decodeHex(value);
            if (decoded != null && actionable(decoded)) findings.add(f(name, raw, sourceHeader, "hexadecimal", decoded));
        }
        return findings;
    }

    private static HeaderFinding f(String name, String raw, String source, String encoding, String decoded) {
        return new HeaderFinding("Structured data encoded in cookie: " + name, source, raw,
                "Cookie '" + name + "' contains " + encoding + "-encoded structured data. " +
                        "Encoding is not encryption; review the decoded contents for sensitive data or " +
                        "application-controlled fields before treating it as a security issue.",
                source + ": " + name + " (" + encoding + ") -> " + truncate(decoded),
                Severity.INFORMATION, Confidence.FIRM, HeaderFinding.Category.AUTH,
                "https://cwe.mitre.org/data/definitions/311.html");
    }

    private static boolean actionable(String value) {
        String trimmed = value.trim();
        if (trimmed.length() < 2 || trimmed.length() > MAX_DECODED) return false;
        if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try { return containsSensitiveField(JsonUtil.parse(trimmed)); }
            catch (IllegalArgumentException ignored) { return false; }
        }
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return SENSITIVE_FIELD.matcher(trimmed).matches();
        }
        if (!FORM.matcher(trimmed).matches()) return false;
        for (String pair : trimmed.split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0 && SENSITIVE_FIELD.matcher(pair.substring(0, equals)).matches()) return true;
        }
        return false;
    }

    private static boolean containsSensitiveField(Object value) {
        if (value instanceof java.util.Map<?, ?> map) {
            for (var entry : map.entrySet()) {
                if (SENSITIVE_FIELD.matcher(String.valueOf(entry.getKey())).matches()) return true;
                if (containsSensitiveField(entry.getValue())) return true;
            }
        } else if (value instanceof java.util.List<?> list) {
            for (Object item : list) if (containsSensitiveField(item)) return true;
        }
        return false;
    }

    private static String decodeUrl(String value) {
        if (!value.contains("%")) return null;
        try { String decoded = URLDecoder.decode(value, StandardCharsets.UTF_8); return decoded.equals(value) ? null : decoded; }
        catch (IllegalArgumentException ignored) { return null; }
    }
    private static String decodeBase64(String value, boolean urlSafe) {
        try {
            String padded = value + "=".repeat((4 - value.length() % 4) % 4);
            byte[] bytes = (urlSafe ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(padded);
            return bytes.length > MAX_DECODED ? null : StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (IllegalArgumentException | CharacterCodingException ignored) { return null; }
    }
    private static String decodeHex(String value) {
        byte[] bytes = new byte[value.length() / 2];
        try {
            for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (IllegalArgumentException | CharacterCodingException ignored) { return null; }
    }
    private static String stripQuotes(String value) { return value.length() > 1 && value.startsWith("\"") && value.endsWith("\"") ? value.substring(1, value.length() - 1) : value; }
    private static String truncate(String value) { return value.length() <= 512 ? value : value.substring(0, 512) + "…"; }
}
