package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Thin, purely-passive wrapper over Montoya's Collaborator API. Quimera never sends anything to
 * Collaborator itself, generatePayload() is an optional convenience so the analyst doesn't have
 * to alt-tab to Burp's own Collaborator client tab, and checkInteractions() only ever reads back
 * whatever has already arrived, however it was triggered (a manual curl, an OOB payload placed by
 * hand in some other tool, a header injected elsewhere). Exactly the "I do the OOB myself, Quimera
 * just tells me what headers (User-Agent etc.) that incoming request carried" workflow requested,
 * no active probing.
 */
public class CollaboratorInspector {

    /** One interaction, already unpacked for display: HTTP-specific fields are null for DNS/SMTP. */
    public record CollaboratorHit(ZonedDateTime time, InteractionType type, String clientIp,
                                   String userAgent, String recognizedClient,
                                   HttpRequestResponse requestResponse) {}

    private final MontoyaApi api;
    private CollaboratorClient client;

    public CollaboratorInspector(MontoyaApi api) {
        this.api = api;
    }

    /** Lazily creates the Collaborator client on first use, no network activity at construction. */
    private CollaboratorClient client() {
        if (client == null) client = api.collaborator().createClient();
        return client;
    }

    /** Generates a fresh interaction domain. Purely a convenience, nothing is sent to it here. */
    public String generatePayload() {
        return client().generatePayload().toString();
    }

    /**
     * Reads back every interaction seen so far by this session's client (DNS, HTTP and SMTP
     * alike), newest first. For HTTP interactions the full request/response and a best-effort
     * User-Agent fingerprint are included, this is the actual "detection" the analyst asked for.
     */
    public List<CollaboratorHit> checkInteractions() {
        List<CollaboratorHit> hits = new ArrayList<>();
        for (Interaction it : client().getAllInteractions()) {
            String userAgent = null;
            HttpRequestResponse rr = null;
            if (it.httpDetails().isPresent()) {
                HttpDetails details = it.httpDetails().get();
                rr = details.requestResponse();
                if (rr != null && rr.request() != null) {
                    userAgent = rr.request().headerValue("User-Agent");
                }
            }
            String clientIp = it.clientIp() != null ? it.clientIp().getHostAddress() : "-";
            hits.add(new CollaboratorHit(it.timeStamp(), it.type(), clientIp,
                    userAgent, fingerprintUserAgent(userAgent), rr));
        }
        hits.sort(Comparator.comparing(CollaboratorHit::time).reversed());
        return hits;
    }

    /**
     * Best-effort recognition of common HTTP client libraries/tools from their default
     * User-Agent, this is what tells the analyst "the request that hit your OOB payload came from
     * a Python script server-side" vs "came from a real browser" at a glance.
     */
    private static String fingerprintUserAgent(String ua) {
        if (ua == null || ua.isBlank()) return "-";
        String l = ua.toLowerCase(Locale.ROOT);
        if (l.startsWith("curl/"))                 return "curl";
        if (l.startsWith("wget/"))                 return "Wget";
        if (l.contains("python-requests"))         return "python-requests";
        if (l.contains("python-urllib"))           return "Python urllib";
        if (l.contains("go-http-client"))          return "Go net/http";
        if (l.contains("postmanruntime"))          return "Postman";
        if (l.contains("okhttp"))                  return "OkHttp (Java/Kotlin/Android)";
        if (l.contains("aws-sdk") || l.contains("aws-internal")) return "AWS SDK";
        if (l.contains("axios"))                   return "Node.js (axios)";
        if (l.contains("node-fetch") || l.contains("node.js"))   return "Node.js";
        if (l.contains("guzzlehttp") || l.contains("php/"))      return "PHP";
        if (l.contains("java/") || l.contains("apache-httpclient")) return "Java HTTP client";
        if (l.contains("ruby"))                    return "Ruby";
        if (l.contains("libwww-perl"))              return "Perl";
        if (l.contains("dart"))                     return "Dart/Flutter";
        if (l.contains("nmap"))                     return "Nmap NSE";
        if (l.contains("masscan"))                   return "Masscan";
        if (l.contains("googlebot") || l.contains("bingbot") || l.contains("crawler")
                || l.contains("spider") || l.contains("bot"))    return "Bot/crawler";
        if (l.contains("mozilla/") && (l.contains("chrome/") || l.contains("safari/")
                || l.contains("firefox/") || l.contains("edg/"))) return "Real browser";
        return "Unrecognized";
    }
}
