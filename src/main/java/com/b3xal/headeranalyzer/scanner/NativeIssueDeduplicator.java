package com.b3xal.headeranalyzer.scanner;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Shared deduplication for native Burp issues emitted by the passive scan check and by the
 * source-aware HTTP listener. The latter is required for request/auth analysis because only it
 * knows whether Proxy, Repeater, Scanner, etc. is enabled in Cookies & Auth settings. */
public final class NativeIssueDeduplicator {
    private NativeIssueDeduplicator() {}
    private static final Set<String> REPORTED = ConcurrentHashMap.newKeySet();

    public static boolean first(String host, String issueName) {
        return REPORTED.add((host == null ? "" : host) + "::" + issueName);
    }
}
