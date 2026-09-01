package com.b3xal.headeranalyzer.scanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.b3xal.headeranalyzer.model.HeaderFinding;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.nio.charset.StandardCharsets;

/** Adds precise Burp message-editor markers for the evidence represented by a finding. */
public final class NativeEvidenceMarker {
    private NativeEvidenceMarker() {}

    public static HttpRequestResponse mark(HttpRequestResponse rr, HeaderFinding finding) {
        if (rr == null || finding == null) return rr;
        try {
            String location = finding.headerName == null ? "" : finding.headerName;
            if (location.equalsIgnoreCase("(response body)"))
                return markResponseValue(rr, finding.headerValue, true);
            if (location.equalsIgnoreCase("(request body)"))
                return markRequestValue(rr, finding.headerValue, true);
            if (location.equalsIgnoreCase("(URL query string)"))
                return markRequestValue(rr, finding.headerValue, false);
            if (isWebStorageLocation(location)) {
                // Browser-bridge evidence is a synthetic JSON response. Prefer the exact stored
                // value so Burp highlights the useful evidence; values requiring JSON escaping
                // may not occur byte-for-byte, in which case highlight the storage bucket label.
                HttpRequestResponse marked = markResponseValue(rr, finding.headerValue, true);
                if (marked != rr) return marked;
                return markResponseValue(rr,
                        location.toLowerCase(Locale.ROOT).contains("sessionstorage")
                                ? "sessionStorage" : "localStorage", true);
            }

            // AUTH headers are request-side except Set-Cookie. Everything else is a response
            // header finding. This keeps an Authorization token out of response markers while
            // preserving the established full-line response-header highlighting.
            if (finding.category == HeaderFinding.Category.AUTH
                    && !location.equalsIgnoreCase("Set-Cookie"))
                return markRequestHeader(rr, location, finding.headerValue);
            return markResponseHeader(rr, location);
        } catch (Exception ignored) {
            return rr;
        }
    }

    private static HttpRequestResponse markResponseValue(HttpRequestResponse rr, String value,
                                                           boolean bodyOnly) {
        if (rr.response() == null || value == null || value.isBlank()) return rr;
        ByteArray raw = rr.response().toByteArray();
        int start = bodyOnly ? rr.response().bodyOffset() : 0;
        int[] range = exactRange(raw.getBytes(), value, start);
        return range == null ? rr : rr.withResponseMarkers(Marker.marker(range[0], range[1]));
    }

    private static HttpRequestResponse markRequestValue(HttpRequestResponse rr, String value,
                                                          boolean bodyOnly) {
        if (rr.request() == null || value == null || value.isBlank()) return rr;
        ByteArray raw = rr.request().toByteArray();
        int start = bodyOnly ? rr.request().bodyOffset() : 0;
        int[] range = exactRange(raw.getBytes(), value, start);
        return range == null ? rr : rr.withRequestMarkers(Marker.marker(range[0], range[1]));
    }

    private static boolean isWebStorageLocation(String location) {
        if (location == null) return false;
        String lower = location.toLowerCase(Locale.ROOT);
        return lower.equals("(browser: localstorage)")
                || lower.equals("(browser: sessionstorage)");
    }

    private static HttpRequestResponse markResponseHeader(HttpRequestResponse rr, String name) {
        if (rr.response() == null || name == null || name.isBlank()) return rr;
        List<Marker> markers = headerLineMarkers(rr.response().toString(), name);
        return markers.isEmpty() ? rr : rr.withResponseMarkers(markers);
    }

    private static HttpRequestResponse markRequestHeader(HttpRequestResponse rr, String name,
                                                           String value) {
        if (rr.request() == null) return rr;
        List<Marker> markers = headerLineMarkers(rr.request().toString(), name);
        if (!markers.isEmpty()) return rr.withRequestMarkers(markers);
        return markRequestValue(rr, value, false);
    }

    private static List<Marker> headerLineMarkers(String raw, String headerName) {
        List<Marker> markers = new ArrayList<>();
        if (raw == null || headerName == null) return markers;
        String lowerRaw = raw.toLowerCase(Locale.ROOT);
        String target = headerName.toLowerCase(Locale.ROOT) + ":";
        int headerEnd = raw.indexOf("\r\n\r\n");
        if (headerEnd < 0) headerEnd = raw.indexOf("\n\n");
        if (headerEnd < 0) headerEnd = raw.length();
        int from = 0;
        while (from < headerEnd) {
            int idx = lowerRaw.indexOf(target, from);
            if (idx < 0 || idx >= headerEnd) break;
            if (idx > 0 && raw.charAt(idx - 1) != '\n') { from = idx + 1; continue; }
            int lineEnd = raw.indexOf('\n', idx);
            if (lineEnd < 0 || lineEnd > headerEnd) lineEnd = headerEnd;
            else lineEnd++;
            int byteStart = raw.substring(0, idx).getBytes(StandardCharsets.UTF_8).length;
            int byteEnd = raw.substring(0, lineEnd).getBytes(StandardCharsets.UTF_8).length;
            markers.add(Marker.marker(byteStart, byteEnd));
            from = lineEnd;
        }
        return markers;
    }

    static int[] exactRange(byte[] raw, String value, int start) {
        if (raw == null || value == null || value.isEmpty()) return null;
        byte[] needle = value.getBytes(StandardCharsets.UTF_8);
        outer: for (int i = Math.max(0, start); i <= raw.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) if (raw[i + j] != needle[j]) continue outer;
            return new int[]{i, i + needle.length};
        }
        return null;
    }
}
