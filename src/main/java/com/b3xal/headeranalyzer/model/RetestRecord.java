package com.b3xal.headeranalyzer.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/** Verification history for one (host, path, issue+header) finding, tracked across retests. */
public class RetestRecord {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    public final String key;
    public FindingStatus status = FindingStatus.OPEN;
    public final LocalDateTime firstSeen;
    public LocalDateTime lastSeen;      // last time this finding was observed present
    public LocalDateTime lastChecked;   // last time this finding's URL was analyzed at all
    public LocalDateTime resolvedAt;    // set when marked RESOLVED (cleared on reopen)

    public RetestRecord(String key) {
        this.key = key;
        this.firstSeen = LocalDateTime.now();
    }

    public String statusSummary() {
        return switch (status) {
            case OPEN     -> "Open, last seen " + fmt(lastSeen);
            case RESOLVED -> "Resolved, verified " + fmt(resolvedAt);
            case REOPENED -> "Reopened, was resolved " + fmt(resolvedAt) + ", seen again " + fmt(lastSeen);
        };
    }

    private static String fmt(LocalDateTime t) {
        return t != null ? t.format(FMT) : "?";
    }
}
