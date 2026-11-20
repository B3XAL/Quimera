package com.b3xal.headeranalyzer.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Regression for the Report "Seen on N of M analyzed requests" counter. A header whose value
 * changes per response (Last-Modified) used to be read off a single representative value and
 * reported as seen once, even when it was present on every analyzed response. */
class ReportDisclosureCountTest {

    @Test
    void lastModifiedPresentOnEveryResponseIsNotCountedAsOne() {
        // 120 responses, each with a distinct Last-Modified date: 120 value-keys, each seen once.
        List<String> valueKeys = new ArrayList<>();
        Map<String, Integer> countByKey = new java.util.HashMap<>();
        for (int i = 0; i < 120; i++) {
            String key = "Last-ModifiedWed, 01 Jan 2026 00:00:" + String.format("%02d", i % 60) + " GMT#" + i;
            valueKeys.add(key);
            countByKey.put(key, 1);
        }

        assertEquals(120, ReportPanel.headerObservationTotal(valueKeys, countByKey, 120));
    }

    @Test
    void constantValuedHeaderKeepsItsAccumulatedCount() {
        // A header with one stable value (Server: nginx) seen on all 120 responses: single key, count 120.
        List<String> valueKeys = List.of("Servernginx");
        Map<String, Integer> countByKey = Map.of("Servernginx", 120);

        assertEquals(120, ReportPanel.headerObservationTotal(valueKeys, countByKey, 120));
    }

    @Test
    void totalIsCappedAtTheNumberOfAnalyzedRows() {
        // Defensive: inventory sources reconciled via max could, at an edge, sum above the row total.
        List<String> valueKeys = List.of("ETaga", "ETagb");
        Map<String, Integer> countByKey = Map.of("ETaga", 80, "ETagb", 80);

        assertEquals(100, ReportPanel.headerObservationTotal(valueKeys, countByKey, 100));
    }

    @Test
    void absentCountsDefaultToOnePerValueKey() {
        List<String> valueKeys = List.of("Viax", "Viay", "Viaz");
        assertEquals(3, ReportPanel.headerObservationTotal(valueKeys, Map.of(), 50));
    }
}
