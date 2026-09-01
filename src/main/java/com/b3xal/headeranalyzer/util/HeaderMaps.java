package com.b3xal.headeranalyzer.util;

import java.util.Map;

/** Builds case-insensitive-by-convention header maps without discarding repeated field lines. */
public final class HeaderMaps {
    private HeaderMaps() {}

    public static void addResponse(Map<String, String> target, String name, String value) {
        add(target, name, value, isNonCombinableResponse(name) ? "\n" : ", ");
    }

    public static void addRequest(Map<String, String> target, String name, String value) {
        add(target, name, value, name.equalsIgnoreCase("Cookie") ? "; " : ", ");
    }

    private static boolean isNonCombinableResponse(String name) {
        return name.equalsIgnoreCase("Set-Cookie")
                || name.equalsIgnoreCase("Content-Security-Policy")
                || name.equalsIgnoreCase("Content-Security-Policy-Report-Only")
                || name.equalsIgnoreCase("Strict-Transport-Security")
                || name.equalsIgnoreCase("X-Frame-Options");
    }

    private static void add(Map<String, String> target, String name, String value, String separator) {
        String existingKey = null;
        for (String key : target.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                existingKey = key;
                break;
            }
        }
        if (existingKey == null) {
            target.put(name, value);
        } else {
            String old = target.get(existingKey);
            target.put(existingKey, old == null || old.isEmpty() ? value : old + separator + value);
        }
    }
}
