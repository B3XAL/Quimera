package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.util.JsonUtil;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Extracts JWTs embedded in structured cookie values. Real applications frequently store an
 * entire OAuth/OIDC response as JSON (sometimes URL- or Base64-encoded) rather than making the
 * cookie value itself a JWT. The ordinary direct-value check cannot see those tokens.
 *
 * This class deliberately parses data only: no Java deserialization, decompression, script
 * execution or speculative decoding. A decoded candidate must be valid UTF-8 and either a JWT or
 * a JSON object/array before it is followed further. Work is bounded by depth, node count and
 * input size so hostile cookies cannot turn passive analysis into an expensive recursive walk.
 */
public final class StructuredCookieJwtAnalyzer {

    private StructuredCookieJwtAnalyzer() {}

    private static final int MAX_DEPTH = 6;
    private static final int MAX_NODES = 200;
    private static final int MAX_TRANSFORMS = 2;
    private static final int MAX_VALUE_LENGTH = 262_144;

    /** One distinct JWT and every structured path at which it occurred. */
    public record ExtractedJwt(String token, List<String> paths) {}
    public record EmbeddedCredential(String path, String fieldName, String value) {}

    public static List<HeaderFinding> analyze(String cookieName, String value, String sourceHeader,
                                               CookiesAndAuthConfig config) {
        if (!config.jwtEnabled) return List.of();
        List<HeaderFinding> findings = new ArrayList<>();
        for (ExtractedJwt extracted : extract(value)) {
            String paths = String.join(", ", extracted.paths());
            String source = sourceHeader + ": " + cookieName
                    + (paths.equals("$") ? "" : " -> " + paths);
            findings.addAll(JwtAnalyzer.analyze(extracted.token(), sourceHeader, source, config));
        }
        return findings;
    }

    /** Pure extraction entry point shared with tests and the browser-bridge parser. */
    public static List<ExtractedJwt> extract(String rawValue) {
        if (rawValue == null || rawValue.isBlank() || rawValue.length() > MAX_VALUE_LENGTH) {
            return List.of();
        }
        State state = new State();
        inspectString(stripCookieQuotes(rawValue.trim()), "$", 0, 0, state);
        List<ExtractedJwt> out = new ArrayList<>();
        state.pathsByToken.forEach((token, paths) -> out.add(new ExtractedJwt(token, List.copyOf(paths))));
        return out;
    }

    /** Opaque (non-JWT) credentials under explicit auth-shaped JSON keys, through the same
     * bounded URL/Base64 decoding pipeline used for embedded JWTs. */
    public static List<EmbeddedCredential> extractOpaqueCredentials(String rawValue) {
        if (rawValue == null || rawValue.isBlank() || rawValue.length() > MAX_VALUE_LENGTH) return List.of();
        State state = new State();
        inspectString(stripCookieQuotes(rawValue.trim()), "$", 0, 0, state);
        return List.copyOf(state.opaqueCredentials);
    }

    /** Replaces one extracted JWT while retaining its surrounding JSON/URL/Base64 container. */
    public static String replaceToken(String rawValue, String oldToken, String newToken) {
        if (rawValue == null || oldToken == null || newToken == null
                || rawValue.length() > MAX_VALUE_LENGTH) return null;
        return replaceInString(rawValue, oldToken, newToken, 0, 0);
    }

    private static String replaceInString(String value, String oldToken, String newToken,
                                          int depth, int transforms) {
        if (depth > MAX_DEPTH || transforms > MAX_TRANSFORMS) return null;
        if (value.equals(oldToken)) return newToken;

        Object parsed = parseStructuredJson(value.trim());
        if (parsed != null) {
            Object replaced = replaceInJson(parsed, oldToken, newToken, depth + 1, transforms);
            if (replaced != null) return JsonUtil.write(replaced);
        }
        if (transforms >= MAX_TRANSFORMS) return null;

        String decoded = urlDecodeIfChanged(value);
        if (decoded != null) {
            String replaced = replaceInString(decoded, oldToken, newToken, depth, transforms + 1);
            if (replaced != null) return URLEncoder.encode(replaced, StandardCharsets.UTF_8);
        }

        for (boolean urlSafe : new boolean[]{false, true}) {
            try {
                byte[] bytes = (urlSafe ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(padBase64(value));
                String text = strictUtf8(bytes);
                String replaced = replaceInString(text, oldToken, newToken, depth, transforms + 1);
                if (replaced != null) {
                    Base64.Encoder encoder = urlSafe ? Base64.getUrlEncoder() : Base64.getEncoder();
                    if (!value.endsWith("=")) encoder = encoder.withoutPadding();
                    return encoder.encodeToString(replaced.getBytes(StandardCharsets.UTF_8));
                }
            } catch (IllegalArgumentException | CharacterCodingException ignored) {
                // Try the other alphabet.
            }
        }
        return null;
    }

    private static Object replaceInJson(Object value, String oldToken, String newToken,
                                        int depth, int transforms) {
        if (depth > MAX_DEPTH) return null;
        if (value instanceof String string) {
            String replaced = replaceInString(string, oldToken, newToken, depth, transforms);
            return replaced == null ? null : replaced;
        }
        if (value instanceof List<?> list) {
            List<Object> copy = new ArrayList<>(list);
            for (int i = 0; i < copy.size(); i++) {
                Object replaced = replaceInJson(copy.get(i), oldToken, newToken, depth + 1, transforms);
                if (replaced != null) { copy.set(i, replaced); return copy; }
            }
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            map.forEach((key, item) -> copy.put(String.valueOf(key), item));
            for (Map.Entry<String, Object> entry : copy.entrySet()) {
                Object replaced = replaceInJson(entry.getValue(), oldToken, newToken, depth + 1, transforms);
                if (replaced != null) { entry.setValue(replaced); return copy; }
            }
        }
        return null;
    }

    private static final class State {
        int nodes;
        final Map<String, List<String>> pathsByToken = new LinkedHashMap<>();
        final Set<String> visitedCandidates = new HashSet<>();
        final List<EmbeddedCredential> opaqueCredentials = new ArrayList<>();

        void jwt(String token, String path) {
            List<String> paths = pathsByToken.computeIfAbsent(token, ignored -> new ArrayList<>());
            if (!paths.contains(path)) paths.add(path);
        }
    }

    private static void inspectString(String candidate, String path, int depth, int transforms, State state) {
        if (candidate == null || candidate.isBlank() || candidate.length() > MAX_VALUE_LENGTH
                || depth > MAX_DEPTH || state.nodes >= MAX_NODES) return;
        state.nodes++;

        String trimmed = candidate.trim();
        if (JwtAnalyzer.looksLikeJwt(trimmed)) {
            state.jwt(trimmed, path);
            return;
        }

        // The same decoded string can be reached through more than one route (for example a
        // percent-encoded Base64 string). Avoid walking it repeatedly while still retaining every
        // JWT occurrence path through State.jwt above.
        String visitKey = depth + "|" + transforms + "|" + trimmed;
        if (!state.visitedCandidates.add(visitKey)) return;

        Object json = parseStructuredJson(trimmed);
        if (json != null) {
            walkJson(json, path, depth + 1, transforms, state);
            return;
        }

        if (transforms >= MAX_TRANSFORMS) return;

        String urlDecoded = urlDecodeIfChanged(trimmed);
        if (urlDecoded != null) inspectString(urlDecoded, path, depth, transforms + 1, state);

        for (String decoded : base64Candidates(trimmed)) {
            inspectString(decoded, path, depth, transforms + 1, state);
        }
    }

    private static void walkJson(Object value, String path, int depth, int transforms, State state) {
        if (value == null || depth > MAX_DEPTH || state.nodes >= MAX_NODES) return;
        state.nodes++;
        if (value instanceof String string) {
            inspectString(string, path, depth, transforms, state);
            return;
        }
        if (value instanceof List<?> list) {
            for (int i = 0; i < list.size() && state.nodes < MAX_NODES; i++) {
                walkJson(list.get(i), path + "[" + i + "]", depth + 1, transforms, state);
            }
            return;
        }
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (state.nodes >= MAX_NODES) break;
                String key = String.valueOf(entry.getKey());
                if (entry.getValue() instanceof String string
                        && WebStorageAnalyzer.isSensitiveKeyName(key.toLowerCase(java.util.Locale.ROOT))
                        && !JwtAnalyzer.looksLikeJwt(string)
                        && WebStorageAnalyzer.looksLikeOpaqueToken(string)) {
                    String credentialPath = appendPath(path, key);
                    boolean duplicate = state.opaqueCredentials.stream().anyMatch(c ->
                            c.path().equals(credentialPath) && c.value().equals(string));
                    if (!duplicate) state.opaqueCredentials.add(
                            new EmbeddedCredential(credentialPath, key, string));
                }
                walkJson(entry.getValue(), appendPath(path, key), depth + 1, transforms, state);
            }
        }
    }

    private static Object parseStructuredJson(String candidate) {
        if (candidate.length() < 2) return null;
        char first = candidate.charAt(0);
        char last = candidate.charAt(candidate.length() - 1);
        if (!((first == '{' && last == '}') || (first == '[' && last == ']')
                || (first == '"' && last == '"'))) return null;
        try {
            Object parsed = JsonUtil.parse(candidate);
            return parsed instanceof Map<?, ?> || parsed instanceof List<?> || parsed instanceof String
                    ? parsed : null;
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static String urlDecodeIfChanged(String value) {
        if (value.indexOf('%') < 0) return null;
        try {
            String decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
            return decoded.equals(value) ? null : decoded;
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static List<String> base64Candidates(String value) {
        if (value.length() < 8 || value.length() > MAX_VALUE_LENGTH || value.matches(".*\\s+.*")) {
            return List.of();
        }
        List<String> out = new ArrayList<>(2);
        decodeBase64(value, false, out);
        decodeBase64(value, true, out);
        return out;
    }

    private static void decodeBase64(String value, boolean urlSafe, List<String> out) {
        try {
            String padded = padBase64(value);
            byte[] bytes = (urlSafe ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(padded);
            String decoded = strictUtf8(bytes);
            if (!decoded.isBlank() && !out.contains(decoded)) out.add(decoded);
        } catch (IllegalArgumentException | CharacterCodingException ignored) {
            // Not valid Base64/Base64URL containing UTF-8 text.
        }
    }

    private static String strictUtf8(byte[] bytes) throws CharacterCodingException {
        CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes));
        return chars.toString();
    }

    private static String padBase64(String value) {
        int rem = value.length() % 4;
        if (rem == 0) return value;
        if (rem == 1) throw new IllegalArgumentException("invalid base64 length");
        return value + (rem == 2 ? "==" : "=");
    }

    private static String stripCookieQuotes(String value) {
        if (value.length() >= 2 && value.charAt(0) == '"' && value.charAt(value.length() - 1) == '"') {
            // A quoted cookie value commonly wraps percent/Base64 data. If it is itself a JSON
            // string, JsonUtil will unescape it later; only strip quotes when the inner content is
            // not JSON-escaped, preventing accidental removal of meaningful backslashes.
            String inner = value.substring(1, value.length() - 1);
            if (inner.indexOf('\\') < 0) return inner;
        }
        return value;
    }

    private static String appendPath(String path, String key) {
        return key.matches("[A-Za-z_$][A-Za-z0-9_$-]*")
                ? path + "." + key
                : path + "[" + JsonUtil.write(key) + "]";
    }
}
