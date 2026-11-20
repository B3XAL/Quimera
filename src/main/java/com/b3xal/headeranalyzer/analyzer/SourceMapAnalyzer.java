package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.util.JsonUtil;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Detects a source map only when the actual captured response proves that it is publicly
 * accessible. Header values such as ETag are deliberately not inputs: they are opaque cache
 * validators, not resource pointers. */
final class SourceMapAnalyzer {
    private SourceMapAnalyzer() {}

    static List<HeaderFinding> analyze(String rawUrl, int statusCode, String body) {
        if (statusCode < 200 || statusCode >= 300 || !isMapPath(rawUrl) || body == null || body.isBlank()) {
            return List.of();
        }

        try {
            Object parsed = JsonUtil.parse(body.trim());
            if (!(parsed instanceof Map<?, ?> map) || !isSourceMap(map)) return List.of();

            int sourceCount = ((List<?>) map.get("sources")).size();
            int embeddedSourceCount = embeddedSourceCount(map.get("sourcesContent"));
            String evidence = "Accessible source map response: " + sourceCount + " source"
                    + (sourceCount == 1 ? "" : "s")
                    + (embeddedSourceCount > 0 ? "; " + embeddedSourceCount + " embedded source file"
                    + (embeddedSourceCount == 1 ? "" : "s") : "");
            if (embeddedSourceCount > 0) {
                return List.of(new HeaderFinding(
                        "Public source map exposes embedded source content",
                        "(source map response)", String.valueOf(sourceCount),
                        "A publicly accessible, valid source map includes sourcesContent, allowing clients to " +
                                "reconstruct original source files. Review the embedded source for secrets and " +
                                "internal implementation details, then remove the map from production or restrict it.",
                        evidence, Severity.MEDIUM, Confidence.CERTAIN,
                        HeaderFinding.Category.INFORMATION_DISCLOSURE,
                        "https://developer.mozilla.org/en-US/docs/Tools/Debugger/How_to/Use_a_source_map"));
            }
            return List.of(new HeaderFinding(
                    "Public source map accessible",
                    "(source map response)", String.valueOf(sourceCount),
                    "A valid source map is publicly accessible. It reveals original source paths and mappings; " +
                            "verify whether the map is intended to be published and whether its source files " +
                            "contain sensitive implementation details.",
                    evidence, Severity.LOW, Confidence.CERTAIN,
                    HeaderFinding.Category.INFORMATION_DISCLOSURE,
                    "https://developer.mozilla.org/en-US/docs/Tools/Debugger/How_to/Use_a_source_map"));
        } catch (RuntimeException ignored) {
            // A .map-looking URL is not sufficient evidence; malformed or oversized JSON is ignored.
            return List.of();
        }
    }

    private static boolean isMapPath(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) return false;
        try {
            String path = URI.create(rawUrl).getPath();
            return path != null && path.toLowerCase(Locale.ROOT).endsWith(".map");
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    private static boolean isSourceMap(Map<?, ?> map) {
        Object version = map.get("version");
        Object sources = map.get("sources");
        Object mappings = map.get("mappings");
        return version instanceof Number n && n.intValue() == 3
                && sources instanceof List<?> list && !list.isEmpty()
                && list.stream().allMatch(String.class::isInstance)
                && mappings instanceof String;
    }

    private static int embeddedSourceCount(Object sourcesContent) {
        if (!(sourcesContent instanceof List<?> list)) return 0;
        return (int) list.stream().filter(value -> value instanceof String s && !s.isBlank()).count();
    }
}
