package com.b3xal.headeranalyzer.model;

import java.util.*;

/**
 * Aggregation helper for TechFinding lists, de-duplicates by product+version
 * while keeping track of which header(s) revealed each entry.
 */
public final class TechInventory {

    private TechInventory() {}

    /** Merge findings from multiple URLs of the same host into a de-duplicated, sorted list. */
    public static List<TechFinding> aggregate(Collection<UrlAnalysisResult> results) {
        Map<String, TechFinding> byKey = new LinkedHashMap<>();
        for (UrlAnalysisResult r : results) {
            for (TechFinding tf : r.techFindings) {
                byKey.putIfAbsent(tf.key(), tf);
            }
        }
        List<TechFinding> out = new ArrayList<>(byKey.values());
        out.sort(Comparator.comparing(t -> t.product.toLowerCase(Locale.ROOT)));
        return out;
    }
}
