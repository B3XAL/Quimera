package com.b3xal.headeranalyzer.ui;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.*;

class VisibleResultStatsTest {
    @Test
    void reloadReplacesCountAndKeepsHostsDistinct() {
        VisibleResultStats stats = new VisibleResultStats();
        stats.put("one", "GET /", 5);
        stats.put("one", "GET /", 2);
        stats.put("two", "GET /", 3);
        stats.put("one", "GET / [probe]", 1);
        assertEquals(6, stats.findings());
        assertEquals(2, stats.hosts());
        stats.put("two", "GET /", 0);
        assertEquals(3, stats.findings());
        assertEquals(2, stats.hosts());
    }

    @Test
    void clearAndScopeRebuildDiscardOldCounts() {
        VisibleResultStats stats = new VisibleResultStats();
        stats.put("hidden", "/", 9);
        stats.clear();
        assertEquals(0, stats.findings());
        assertEquals(0, stats.hosts());
        stats.put("visible", "/", 2);
        assertEquals(2, stats.findings());
        assertEquals(1, stats.hosts());
    }

    @Test
    void largeHistoryAndRepeatedReloadsStayWithinInteractiveBudget() {
        assertTimeout(Duration.ofSeconds(5), () -> {
            VisibleResultStats stats = new VisibleResultStats();
            for (int i = 0; i < 100_000; i++) stats.put("host", "/" + i, 3);
            for (int reload = 0; reload < 10; reload++) {
                for (int i = 0; i < 10_000; i++) stats.put("host", "/" + i, 2);
            }
            assertEquals(290_000, stats.findings());
            assertEquals(1, stats.hosts());
        });
    }
}
