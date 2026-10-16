package com.b3xal.headeranalyzer.ui;

import java.util.HashMap;
import java.util.Map;

/** EDT-owned counters. Retains counts only, never HTTP exchanges or finding objects. */
final class VisibleResultStats {
    private final Map<String, Map<String, Integer>> counts = new HashMap<>();
    private int findings;

    void put(String host, String rowKey, int count) {
        Integer previous = counts.computeIfAbsent(host, ignored -> new HashMap<>()).put(rowKey, count);
        findings += count - (previous == null ? 0 : previous);
    }

    int findings() { return findings; }
    int hosts() { return counts.size(); }

    void clear() {
        counts.clear();
        findings = 0;
    }
}
