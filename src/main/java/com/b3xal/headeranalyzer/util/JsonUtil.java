package com.b3xal.headeranalyzer.util;

import java.util.*;

/**
 * Minimal, dependency-free JSON reader/writer.
 *
 * Parses into plain java.util types: Map&lt;String,Object&gt;, List&lt;Object&gt;,
 * String, Boolean, Double, or null, enough to round-trip Quimera's rule definitions
 * and settings without pulling in Gson/Jackson (extension ships as a single fat jar).
 *
 * Not a general-purpose JSON library: no streaming, no custom object mapping.
 */
public final class JsonUtil {

    private JsonUtil() {}

    // ------ Writing ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(value, sb, 0);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(Object value, StringBuilder sb, int indent) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String s) {
            writeString(s, sb);
        } else if (value instanceof Boolean b) {
            sb.append(b.toString());
        } else if (value instanceof Number n) {
            sb.append(formatNumber(n));
        } else if (value instanceof Map<?, ?> map) {
            writeObject((Map<String, Object>) map, sb, indent);
        } else if (value instanceof List<?> list) {
            writeArray(list, sb, indent);
        } else {
            writeString(String.valueOf(value), sb);
        }
    }

    /** parse() only ever produces Double for numbers (see below), and Double.toString() switches
     * to scientific notation outside roughly [1e-3, 1e7), exactly the range JWT epoch-second
     * timestamps (exp/iat/nbf/auth_time) live in, "1.787656718E9" instead of "1787656718". Whole
     * numbers within a sane range get written as plain integers instead; genuinely fractional or
     * absurdly large values fall back to Double's own formatting unchanged. */
    private static String formatNumber(Number n) {
        double d = n.doubleValue();
        if (!Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d) && Math.abs(d) < 1e15) {
            return String.valueOf((long) d);
        }
        return n.toString();
    }

    private static void writeObject(Map<String, Object> map, StringBuilder sb, int indent) {
        if (map.isEmpty()) { sb.append("{}"); return; }
        sb.append("{\n");
        int i = 0, n = map.size();
        for (Map.Entry<String, Object> e : map.entrySet()) {
            pad(sb, indent + 1);
            writeString(e.getKey(), sb);
            sb.append(": ");
            writeValue(e.getValue(), sb, indent + 1);
            if (++i < n) sb.append(',');
            sb.append('\n');
        }
        pad(sb, indent);
        sb.append('}');
    }

    private static void writeArray(List<?> list, StringBuilder sb, int indent) {
        if (list.isEmpty()) { sb.append("[]"); return; }
        sb.append("[\n");
        for (int i = 0; i < list.size(); i++) {
            pad(sb, indent + 1);
            writeValue(list.get(i), sb, indent + 1);
            if (i < list.size() - 1) sb.append(',');
            sb.append('\n');
        }
        pad(sb, indent);
        sb.append(']');
    }

    private static void pad(StringBuilder sb, int indent) {
        for (int i = 0; i < indent; i++) sb.append("  ");
    }

    private static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }

    // ------ Parsing ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public static Object parse(String json) {
        if (json == null) throw new IllegalArgumentException("JSON must not be null");
        if (json.length() > 4 * 1024 * 1024) throw new IllegalArgumentException("JSON exceeds 4 MiB limit");
        Parser p = new Parser(json);
        p.skipWs();
        Object v = p.parseValue();
        p.skipWs();
        if (!p.atEnd()) throw new IllegalArgumentException("Trailing data after JSON value at " + p.position());
        return v;
    }

    private static final class Parser {
        private final String s;
        private int i = 0;

        Parser(String s) { this.s = s; }

        void skipWs() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
        boolean atEnd() { return i >= s.length(); }
        int position() { return i; }

        char peek() {
            if (i >= s.length()) throw new IllegalArgumentException("Unexpected end of JSON at " + i);
            return s.charAt(i);
        }

        Object parseValue() {
            skipWs();
            char c = peek();
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't', 'f' -> parseBoolean();
                case 'n' -> { expect("null"); yield null; }
                default -> parseNumber();
            };
        }

        Map<String, Object> parseObject() {
            expectChar('{');
            LinkedHashMap<String, Object> map = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') { i++; return map; }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                expectChar(':');
                Object val = parseValue();
                map.put(key, val);
                skipWs();
                char c = peek();
                if (c == ',') { i++; continue; }
                if (c == '}') { i++; break; }
                throw new IllegalArgumentException("Expected ',' or '}' at " + i);
            }
            return map;
        }

        List<Object> parseArray() {
            expectChar('[');
            List<Object> list = new ArrayList<>();
            skipWs();
            if (peek() == ']') { i++; return list; }
            while (true) {
                Object val = parseValue();
                list.add(val);
                skipWs();
                char c = peek();
                if (c == ',') { i++; continue; }
                if (c == ']') { i++; break; }
                throw new IllegalArgumentException("Expected ',' or ']' at " + i);
            }
            return list;
        }

        String parseString() {
            expectChar('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') break;
                if (c == '\\') {
                    char esc = s.charAt(i++);
                    switch (esc) {
                        case '"'  -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/'  -> sb.append('/');
                        case 'n'  -> sb.append('\n');
                        case 'r'  -> sb.append('\r');
                        case 't'  -> sb.append('\t');
                        case 'b'  -> sb.append('\b');
                        case 'f'  -> sb.append('\f');
                        case 'u'  -> {
                            String hex = s.substring(i, i + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            i += 4;
                        }
                        default -> sb.append(esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        Boolean parseBoolean() {
            if (s.startsWith("true", i))  { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            throw new IllegalArgumentException("Invalid boolean at " + i);
        }

        Double parseNumber() {
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            return Double.parseDouble(s.substring(start, i));
        }

        void expectChar(char c) {
            skipWs();
            if (peek() != c) throw new IllegalArgumentException("Expected '" + c + "' at " + i);
            i++;
        }

        void expect(String literal) {
            if (!s.startsWith(literal, i)) throw new IllegalArgumentException("Expected '" + literal + "' at " + i);
            i += literal.length();
        }
    }

    // ------ Typed accessors for the parsed Map<String,Object> shape ------------------------------------------------

    public static String str(Map<String, Object> m, String key, String def) {
        Object v = m.get(key);
        return v instanceof String s ? s : def;
    }

    public static boolean bool(Map<String, Object> m, String key, boolean def) {
        Object v = m.get(key);
        return v instanceof Boolean b ? b : def;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> list(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v instanceof List<?> l ? (List<Object>) l : List.of();
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> objectList(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) if (o instanceof Map<?, ?> map) out.add((Map<String, Object>) map);
        }
        return out;
    }
}
