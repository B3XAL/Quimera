package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.b3xal.headeranalyzer.util.JsonUtil;

import java.util.List;
import java.util.Map;

/** Conservative response equivalence for active authentication probes. */
final class ResponseSimilarity {
    private ResponseSimilarity() {}

    static boolean equivalent(HttpResponse a, HttpResponse b) {
        return a != null && b != null
                && equivalent(a.statusCode(), a.bodyToString(), b.statusCode(), b.bodyToString());
    }

    static boolean equivalent(int statusA, String bodyA, int statusB, String bodyB) {
        return statusA == statusB && normalize(bodyA).equals(normalize(bodyB));
    }

    private static String normalize(String body) {
        String value = body == null ? "" : body.trim();
        if (value.isEmpty()) return value;
        char first = value.charAt(0);
        if (first == '{' || first == '[') {
            try {
                Object parsed = JsonUtil.parse(value);
                if (parsed instanceof Map<?, ?> || parsed instanceof List<?>) return JsonUtil.write(parsed);
            } catch (RuntimeException ignored) {
                // Fall through to a whitespace-only normalization for non-JSON bodies.
            }
        }
        return value.replaceAll("\\s+", " ");
    }
}
