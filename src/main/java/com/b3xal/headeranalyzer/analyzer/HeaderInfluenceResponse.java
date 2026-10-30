package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/** Bounded response-only observation. Never searches the request or the rendered evidence. */
final class HeaderInfluenceResponse {
    static final int MAX_BODY = 512 * 1024;
    private static final Set<String> VOLATILE = Set.of("date", "age", "expires", "last-modified",
            "etag", "content-length", "set-cookie", "server-timing", "x-request-id", "x-correlation-id",
            "cf-ray", "traceparent", "tracestate", "x-amzn-trace-id", "x-amz-cf-id", "x-timer");
    private static final Pattern UUID = Pattern.compile(
            "(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b");
    private static final Pattern TIMESTAMP = Pattern.compile(
            "\\b20\\d{2}-\\d{2}-\\d{2}[T ][0-9:.]+Z?\\b");
    final int status;
    final Map<String, List<String>> headers;
    final String body;
    final boolean bodyComplete;

    HeaderInfluenceResponse(int status, Map<String, List<String>> headers, String body, boolean complete) {
        this.status = status;
        this.headers = headers;
        this.body = body;
        this.bodyComplete = complete;
    }

    static HeaderInfluenceResponse of(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return null;
        Map<String, List<String>> headers = new TreeMap<>();
        rr.response().headers().forEach(h -> headers.computeIfAbsent(h.name().toLowerCase(Locale.ROOT),
                ignored -> new ArrayList<>()).add(h.value()));
        int status = rr.response().statusCode();
        String type = String.join(", ", headers.getOrDefault("content-type", List.of())).toLowerCase(Locale.ROOT).trim();
        String mime = type.split(";", 2)[0].trim();
        boolean text = mime.isEmpty() || mime.startsWith("text/") || mime.equals("application/json")
                || mime.endsWith("+json") || mime.equals("application/xml") || mime.endsWith("+xml")
                || mime.equals("application/javascript");
        if (!text || "HEAD".equalsIgnoreCase(rr.request().method()) || status == 204 || status == 205 || status == 304)
            return new HeaderInfluenceResponse(status, headers, "", false);
        try {
            if (rr.response().body().length() > MAX_BODY)
                return new HeaderInfluenceResponse(status, headers, "", false);
            byte[] bytes = rr.response().body().getBytes();
            String encoding = String.join(",", headers.getOrDefault("content-encoding", List.of())).trim();
            String[] codings = encoding.isEmpty() ? new String[0] : encoding.split(",", -1);
            if (codings.length > 3) return new HeaderInfluenceResponse(status, headers, "", false);
            for (int i = codings.length - 1; i >= 0; i--) {
                String coding = codings[i].trim();
                InputStream input = new ByteArrayInputStream(bytes);
                if (coding.equalsIgnoreCase("gzip")) input = new GZIPInputStream(input);
                else if (coding.equalsIgnoreCase("deflate")) input = new InflaterInputStream(input);
                else if (!coding.equalsIgnoreCase("identity"))
                    return new HeaderInfluenceResponse(status, headers, "", false);
                try (InputStream decoded = input) { bytes = decoded.readNBytes(MAX_BODY + 1); }
                if (bytes.length > MAX_BODY) return new HeaderInfluenceResponse(status, headers, "", false);
            }
            if (bytes.length > MAX_BODY) return new HeaderInfluenceResponse(status, headers, "", false);
            Charset charset = StandardCharsets.UTF_8;
            var match = Pattern.compile("charset\\s*=\\s*[\"']?([a-zA-Z0-9_-]+)").matcher(type);
            if (match.find()) charset = Charset.forName(match.group(1));
            String decoded = charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            return new HeaderInfluenceResponse(status, headers, decoded, true);
        } catch (Exception ignored) {
            // Unsupported encoding, truncated compression or unknown charset: headers still usable.
            return new HeaderInfluenceResponse(status, headers, "", false);
        }
    }

    boolean allowedStatus() { return status >= 200 && status < 400 && status != 304; }

    boolean errorPage() {
        String lower = body.toLowerCase(Locale.ROOT);
        return lower.contains("<title>404") || lower.contains("<title>403")
                || lower.contains("<title>500") || lower.contains("<title>access denied")
                || lower.contains("<title>just a moment") || lower.contains("cf-chl-")
                || lower.contains("<title>request blocked") || lower.contains("<title>not found");
    }

    Map<String, String> flatHeaders() {
        Map<String, String> out = new LinkedHashMap<>();
        headers.forEach((k, v) -> out.put(k, String.join("\n", v)));
        return out;
    }

    boolean contains(String value) {
        return body.contains(value) || headers.values().stream().flatMap(Collection::stream)
                .anyMatch(v -> v.contains(value));
    }

    /** Keys describe the response sink; snippets retain the literal bytes after decoding. */
    Map<String, String> reflections(String marker) {
        Map<String, String> hits = new LinkedHashMap<>();
        if (marker.length() < 16) return hits;
        headers.forEach((name, values) -> {
            for (String value : values) if (value.contains(marker))
                hits.put("response header " + name, excerpt(value, value.indexOf(marker)));
        });
        int index = body.indexOf(marker);
        if (index >= 0 && bodyComplete) {
            String mime = String.join(",", headers.getOrDefault("content-type", List.of("unspecified MIME")));
            String context = mime.toLowerCase(Locale.ROOT).contains("html") ? htmlContext(body, index) : mime;
            hits.put("response body (" + context + ")", "decoded offset " + index + ": " + excerpt(body, index));
        }
        return hits;
    }

    private static String htmlContext(String body, int at) {
        String prefix = body.substring(Math.max(0, at - 4096), at).toLowerCase(Locale.ROOT);
        if (prefix.lastIndexOf("<script") > prefix.lastIndexOf("</script")) return "HTML script region; execution unverified";
        if (prefix.lastIndexOf("<!--") > prefix.lastIndexOf("-->")) return "HTML comment";
        if (prefix.lastIndexOf('<') > prefix.lastIndexOf('>')) return "HTML tag/attribute region";
        return "HTML text";
    }

    static String excerpt(String text, int index) {
        return text.substring(Math.max(0, index - 80), Math.min(text.length(), index + 220));
    }

    String signature(String controlledValue) {
        return signature(controlledValue, true);
    }

    String signature(String controlledValue, boolean includeBody) {
        StringBuilder signature = new StringBuilder().append(status).append('\n');
        headers.forEach((name, values) -> {
            if (!VOLATILE.contains(name)) signature.append(name).append(':')
                    .append(normalize(String.join("\n", values), controlledValue)).append('\n');
        });
        if (includeBody && bodyComplete) signature.append(normalize(body, controlledValue));
        else if (includeBody) signature.append("[body not evaluated]");
        return signature.toString();
    }

    private static String normalize(String value, String controlled) {
        if (controlled != null && !controlled.isEmpty()) value = value.replace(controlled, "{controlled}");
        return TIMESTAMP.matcher(UUID.matcher(value).replaceAll("{uuid}")).replaceAll("{timestamp}");
    }
}
