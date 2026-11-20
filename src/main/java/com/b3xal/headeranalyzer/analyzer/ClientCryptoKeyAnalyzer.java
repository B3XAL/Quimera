package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Conservative static detection of literal symmetric-key material in client-delivered code. */
final class ClientCryptoKeyAnalyzer {
    private ClientCryptoKeyAnalyzer() { }
    private static final int MAX_BODY = 2_000_000;
    private static final int MAX_FINDINGS = 12;
    private record Rule(String family, Pattern pattern) { }
    private static final List<Rule> RULES = List.of(
            new Rule("CryptoJS AES", Pattern.compile("(?is)(?:CryptoJS\\s*\\.\\s*)?AES\\s*\\.\\s*(?:encrypt|decrypt)\\s*\\(\\s*[^,]{1,4096},\\s*['\\\"]([^'\\\"\\r\\n]{6,512})['\\\"]")),
            new Rule("CryptoJS symmetric cipher", Pattern.compile("(?is)CryptoJS\\s*\\.\\s*(?:DES|TripleDES|RC4|Rabbit)\\s*\\.\\s*(?:encrypt|decrypt)\\s*\\(\\s*[^,]{1,4096},\\s*['\\\"]([^'\\\"\\r\\n]{6,512})['\\\"]")),
            new Rule("Node symmetric cipher", Pattern.compile("(?is)(?:createCipheriv|createDecipheriv)\\s*\\(\\s*['\\\"](?:aes|des|rc4)[^'\\\"]*['\\\"]\\s*,\\s*['\\\"]([^'\\\"\\r\\n]{6,512})['\\\"]")),
            new Rule("SJCL", Pattern.compile("(?is)sjcl\\s*\\.\\s*(?:encrypt|decrypt)\\s*\\(\\s*['\\\"]([^'\\\"\\r\\n]{6,512})['\\\"]\\s*,")),
            new Rule("node-forge AES", Pattern.compile("(?is)forge\\s*\\.\\s*cipher\\s*\\.\\s*create(?:Cipher|Decipher)\\s*\\(\\s*['\\\"]AES-[^'\\\"]+['\\\"]\\s*,\\s*['\\\"]([^'\\\"\\r\\n]{6,512})['\\\"]")),
            new Rule("Web Crypto AES key import", Pattern.compile("(?is)subtle\\s*\\.\\s*importKey\\s*\\(\\s*['\\\"]raw['\\\"]\\s*,[^;]{0,1024}?['\\\"]([^'\\\"\\r\\n]{6,512})['\\\"][^;]{0,1024}?AES-(?:GCM|CBC|CTR|KW)")));
    private static final List<Rule> VARIABLE_RULES = List.of(
            new Rule("CryptoJS AES", Pattern.compile("(?is)(?:CryptoJS\\s*\\.\\s*)?AES\\s*\\.\\s*(?:encrypt|decrypt)\\s*\\(\\s*[^,]{1,4096},\\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\\s*\\)")),
            new Rule("CryptoJS symmetric cipher", Pattern.compile("(?is)CryptoJS\\s*\\.\\s*(?:DES|TripleDES|RC4|Rabbit)\\s*\\.\\s*(?:encrypt|decrypt)\\s*\\(\\s*[^,]{1,4096},\\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\\s*\\)")),
            new Rule("Node symmetric cipher", Pattern.compile("(?is)(?:createCipheriv|createDecipheriv)\\s*\\(\\s*['\\\"](?:aes|des|rc4)[^'\\\"]*['\\\"]\\s*,\\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\\s*,")),
            new Rule("SJCL", Pattern.compile("(?is)sjcl\\s*\\.\\s*(?:encrypt|decrypt)\\s*\\(\\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\\s*,")),
            new Rule("node-forge AES", Pattern.compile("(?is)forge\\s*\\.\\s*cipher\\s*\\.\\s*create(?:Cipher|Decipher)\\s*\\(\\s*['\\\"]AES-[^'\\\"]+['\\\"]\\s*,\\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\\s*\\)")));
    private static final Pattern STRING_CONSTANT = Pattern.compile(
            "(?m)(?:^|[;{}\\s])(?:const|let|var)\\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\\s*=\\s*['\\\"]([^'\\\"\\r\\n]{6,512})['\\\"]");

    static List<HeaderFinding> analyze(String body, String contentType, String rawUrl) {
        if (body == null || body.length() > MAX_BODY || binary(contentType)) return List.of();
        List<HeaderFinding> findings = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Rule rule : RULES) scan(rule, body, null, findings, seen);
        Map<String, String> constants = stringConstants(body);
        for (Rule rule : VARIABLE_RULES) scan(rule, body, constants, findings, seen);
        return findings;
    }

    private static void scan(Rule rule, String body, Map<String, String> constants,
                             List<HeaderFinding> findings, Set<String> seen) {
            Matcher matcher = rule.pattern.matcher(body);
            while (matcher.find() && findings.size() < MAX_FINDINGS) {
                String captured = matcher.group(1).trim();
                String key = constants == null ? captured : constants.get(captured);
                if (key == null) continue;
                if (!usableKey(key) || !seen.add(rule.family + "\u0001" + key)) continue;
                String evidence = matcher.group().length() <= 1024 ? matcher.group() : matcher.group().substring(0, 1024);
                findings.add(new HeaderFinding("Client-delivered symmetric encryption key: " + rule.family,
                        "(response body)", key,
                        "Client-delivered code passes a literal value in a symmetric encryption-key position. "
                                + "A key shipped to every browser cannot keep client-side encrypted data confidential. "
                                + "Verify whether this is a real production key and move confidentiality-sensitive "
                                + "cryptographic operations and key material to a trusted server-side boundary.",
                        "Client key material: " + key + "\nCall: " + evidence,
                        Severity.LOW, Confidence.FIRM, HeaderFinding.Category.AUTH));
            }
    }

    private static Map<String, String> stringConstants(String body) {
        Map<String, String> constants = new LinkedHashMap<>();
        Matcher matcher = STRING_CONSTANT.matcher(body);
        while (matcher.find() && constants.size() < 128) constants.putIfAbsent(matcher.group(1), matcher.group(2));
        return constants;
    }

    private static boolean binary(String contentType) {
        if (contentType == null) return false;
        String mime = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return mime.startsWith("image/") || mime.startsWith("audio/") || mime.startsWith("video/")
                || mime.startsWith("font/") || mime.equals("application/pdf") || mime.equals("application/octet-stream");
    }

    private static boolean usableKey(String key) {
        String lower = key.toLowerCase(Locale.ROOT);
        return !lower.matches(".*(?:example|sample|placeholder|changeme|replace|your[_ -]?(?:key|secret|password)).*")
                && !key.matches("(?i)^(?:iv|nonce|salt|aad|tag)$")
                && !key.matches("(?s).*\\b(?:this|window|document)\\.[A-Za-z_$][A-Za-z0-9_$.]*.*");
    }
}
