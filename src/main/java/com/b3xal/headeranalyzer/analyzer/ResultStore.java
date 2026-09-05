package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.DomainData;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.TechFinding;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.util.JsonUtil;
import com.b3xal.headeranalyzer.util.SafeLogging;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Persists Logger/Cookies findings into the Burp project so they survive closing and reopening
 * it, the same durability {@link RuleStore} already gives custom rules and
 * {@link com.b3xal.headeranalyzer.config.QuimeraSettings} gives settings.
 *
 * Deliberately scoped to only URLs that produced at least one {@link HeaderFinding} (a real,
 * user-visible decision, see the "solo filas con hallazgos" choice): a "clean" page with zero
 * findings adds nothing Quimera itself computed that Burp's own Proxy History/Site Map doesn't
 * already retain, persisting those too would multiply project-file writes and size for traffic
 * that Quimera has nothing further to say about, with no benefit on reopen.
 *
 * The evidence request/response IS persisted (via Montoya's own native HttpRequest/HttpResponse
 * persistence, not a hand-rolled byte dump) for every finding-bearing row, so Retest and the
 * Request/Response viewer keep working exactly the same after reopening the project as they did
 * in the original session.
 */
public class ResultStore {

    private static final String ROOT_KEY = "quimeraResultsByHost";

    // A single common finding (e.g. "Content modification timestamp disclosure" on Last-Modified,
    // which every static asset on a site can carry) would otherwise persist one full request/
    // response PER URL, thousands of them on a large site for evidence that's the same class of
    // low-severity disclosure every time. Capped per (host, finding-type) combination instead, at
    // a limit generous enough to keep plenty of real examples without scaling with total traffic
    // volume (user's own call: 200 stays cheap even summed across every finding type on a host,
    // nowhere near the cost of 12000 duplicate request/response pairs for the same disclosure). A
    // row is still persisted whenever it carries at least one finding type that hasn't hit its own
    // cap yet, so a rare disclosure riding along on the same response as a common one is never
    // dropped just because the common one is already over quota.
    private static final int MAX_PERSISTED_PER_FINDING_TYPE = 200;

    private final PersistedObject persistence; // may be null (persistence unavailable / tests)
    private final MontoyaApi api;              // may be null in tests, used for logging only
    // host + " " + finding.aggregationKey() -> how many rows carrying that finding type have
    // been persisted so far. Primed from whatever was already on disk in loadInto(), so the cap is
    // respected across restarts too, not just within one running session.
    private final ConcurrentHashMap<String, AtomicInteger> persistedCounts = new ConcurrentHashMap<>();

    public ResultStore(PersistedObject persistence, MontoyaApi api) {
        this.persistence = persistence;
        this.api         = api;
    }

    /** Called once at startup, before the UI is shown, so the Logger/Cookies/Report tabs open
     * already populated instead of looking freshly empty until new traffic arrives. */
    public void loadInto(ConcurrentHashMap<String, DomainData> domainStore) {
        if (persistence == null) return;
        try {
            PersistedObject root = persistence.getChildObject(ROOT_KEY);
            if (root == null) return;
            int loaded = 0;
            for (String host : root.childObjectKeys()) {
                PersistedObject hostObj = root.getChildObject(host);
                if (hostObj == null) continue;
                DomainData dd = domainStore.computeIfAbsent(host, DomainData::new);
                for (String rowKey : hostObj.childObjectKeys()) {
                    try {
                        PersistedObject rowObj = hostObj.getChildObject(rowKey);
                        UrlAnalysisResult result = loadRow(rowObj);
                        if (result == null) continue;
                        dd.addResult(result);
                        // Only a row that actually carried the (expensive, quota-capped) exchange
                        // consumed quota when it was first persisted, a metadata-only row didn't.
                        if (result.originalRequest != null) {
                            for (HeaderFinding f : result.findings) countKey(host, f).incrementAndGet();
                        }
                        loaded++;
                    } catch (Exception rowEx) {
                        // One corrupted row must not sink every other persisted finding.
                        SafeLogging.error(api, "[Quimera] failed to restore persisted result "
                                + host + " " + rowKey + ": " + rowEx.getMessage());
                    }
                }
            }
            SafeLogging.output(api, "[Quimera] restored " + loaded + " persisted finding(s) from the project.");
        } catch (Exception ex) {
            SafeLogging.error(api, "[Quimera] failed to load persisted results: " + ex.getMessage());
        }
    }

    /** Called from the Logger's "Clear" action: persisted findings must actually go away, not
     * silently reappear the next time the project is reopened because only the in-memory
     * domainStore was wiped. */
    public void clearAll() {
        persistedCounts.clear();
        if (persistence == null) return;
        try {
            persistence.deleteChildObject(ROOT_KEY);
        } catch (Exception ex) {
            SafeLogging.error(api, "[Quimera] failed to clear persisted results: " + ex.getMessage());
        }
    }

    /** Call for every result as it's produced (same place {@link DomainData#addResult} is called).
     * A no-op only when there are no findings at all, see the class javadoc. The finding text
     * itself (URL, header, severity, evidence) is always persisted, that's plain text and cheap
     * even across thousands of URLs sharing the same common, low-severity disclosure (a real
     * example: "Content modification timestamp disclosure" on Last-Modified, which nearly every
     * static asset on a site can carry). Only the actual HTTP request/response objects, the
     * expensive part, are capped per (host, finding type), see {@link #hasQuotaRemaining}: past
     * the cap, the finding is still fully recorded and restored, it just won't have a live
     * Request/Response/Retest available for that specific row after reopening the project. */
    public void persist(UrlAnalysisResult result) {
        if (persistence == null || result.findings.isEmpty()) return;
        boolean hasExchange = result.originalRequest != null && result.originalResponse != null;
        boolean includeExchange = hasExchange && hasQuotaRemaining(result);
        try {
            PersistedObject root = persistence.getChildObject(ROOT_KEY);
            if (root == null) root = PersistedObject.persistedObject();
            PersistedObject hostObj = root.getChildObject(result.host);
            if (hostObj == null) hostObj = PersistedObject.persistedObject();
            hostObj.setChildObject(result.rowKey(), buildRow(result, includeExchange));
            // Re-attach at every level unconditionally, not only the first time each object is
            // created: PersistedObject's own mutation semantics (live reference vs. snapshot
            // copy once fetched back via getChildObject) aren't documented, and getting this wrong
            // is exactly the kind of bug that looks fine all session (everything is still the same
            // in-memory object graph) and only shows up as "findings are gone" after actually
            // closing and reopening the project, i.e. impossible to catch without doing this.
            root.setChildObject(result.host, hostObj);
            persistence.setChildObject(ROOT_KEY, root);
            // Only a row that actually got an exchange attached should spend quota; a result with
            // no captured request/response (hasExchange == false) has nothing to cap in the first
            // place and must not silently consume another finding's allowance.
            if (includeExchange) {
                for (HeaderFinding f : result.findings) countKey(result.host, f).incrementAndGet();
            }
        } catch (Exception ex) {
            // Never let a persistence hiccup break live analysis, same posture as RuleStore.save().
            SafeLogging.error(api, "[Quimera] failed to persist result for " + result.url + ": " + ex.getMessage());
        }
    }

    /** True as soon as at least one finding on this result hasn't hit
     * {@link #MAX_PERSISTED_PER_FINDING_TYPE} yet for this host: a rare disclosure must not be
     * dropped just because it happens to ride along on the same response as a common one that IS
     * already over quota. */
    // Package-private (not private): exercised directly by ResultStoreTest, since persist()/
    // loadInto() themselves call Montoya's PersistedObject.persistedObject()/PersistedList static
    // factories, which throw NullPointerException outside a real, running Burp instance (their
    // backing ObjectFactoryLocator is only initialised by Burp itself at extension load), so the
    // Montoya-integration methods can only be exercised by compilation + code review, the same
    // testing posture already accepted for ActiveHeaderScanner's live-HTTP probe methods.
    boolean hasQuotaRemaining(UrlAnalysisResult result) {
        for (HeaderFinding f : result.findings) {
            if (countKey(result.host, f).get() < MAX_PERSISTED_PER_FINDING_TYPE) return true;
        }
        return false;
    }

    AtomicInteger countKey(String host, HeaderFinding finding) {
        return persistedCounts.computeIfAbsent(host + " " + finding.aggregationKey(),
                ignored -> new AtomicInteger());
    }

    // ------ One row: metadata as JSON, HTTP messages via Montoya's own native persistence ------

    private PersistedObject buildRow(UrlAnalysisResult result, boolean includeExchange) {
        PersistedObject row = PersistedObject.persistedObject();
        row.setString("json", toJson(result));
        if (!includeExchange) return row;
        if (result.originalRequest != null && result.originalResponse != null) {
            row.setHttpRequestResponse("exchange",
                    HttpRequestResponse.httpRequestResponse(result.originalRequest, result.originalResponse));
        }
        if (!result.probeExchanges.isEmpty()) {
            PersistedList<HttpRequestResponse> list = PersistedList.persistedHttpRequestResponseList();
            list.addAll(result.probeExchanges);
            row.setHttpRequestResponseList("probeExchanges", list);
        }
        if (!result.probeExchangeLabels.isEmpty()) {
            PersistedList<String> labels = PersistedList.persistedStringList();
            labels.addAll(result.probeExchangeLabels);
            row.setStringList("probeExchangeLabels", labels);
        }
        return row;
    }

    private UrlAnalysisResult loadRow(PersistedObject row) {
        if (row == null) return null;
        String json = row.getString("json");
        if (json == null) return null;
        UrlAnalysisResult result = fromJson(json);
        if (result == null) return null;

        HttpRequestResponse exchange = row.getHttpRequestResponse("exchange");
        if (exchange != null) {
            result.originalRequest  = exchange.request();
            result.originalResponse = exchange.response();
            try {
                result.rawRequest  = exchange.request().toString();
                result.rawResponse = exchange.response().toString();
            } catch (Exception ignored) { /* best-effort raw dump, findings/metadata already loaded */ }
        }
        PersistedList<HttpRequestResponse> probeExchanges = row.getHttpRequestResponseList("probeExchanges");
        if (probeExchanges != null) result.probeExchanges = List.copyOf(probeExchanges);
        PersistedList<String> labels = row.getStringList("probeExchangeLabels");
        if (labels != null) result.probeExchangeLabels = List.copyOf(labels);
        return result;
    }

    // ------ JSON metadata (findings/techFindings/basic fields), via the existing dependency-free JsonUtil ------

    // Package-private: pure String/Map logic with zero Montoya dependency, the actual round-trip
    // risk (enum names, null handling, nested lists), fully testable without a live Burp instance.
    @SuppressWarnings("unchecked")
    String toJson(UrlAnalysisResult result) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("url", result.url);
        m.put("host", result.host);
        m.put("path", result.path);
        m.put("method", result.method);
        m.put("statusCode", result.statusCode);
        m.put("contentLength", result.contentLength);
        m.put("probeLabel", result.probeLabel);
        m.put("timestamp", result.timestamp.toString());
        m.put("rawHeaders", new LinkedHashMap<>(result.rawHeaders));

        List<Object> findings = new ArrayList<>();
        for (HeaderFinding f : result.findings) {
            Map<String, Object> fm = new LinkedHashMap<>();
            fm.put("issueName", f.issueName);
            fm.put("headerName", f.headerName);
            fm.put("headerValue", f.headerValue);
            fm.put("description", f.description);
            fm.put("evidence", f.evidence);
            fm.put("severity", f.severity.name());
            fm.put("confidence", f.confidence.name());
            fm.put("category", f.category.name());
            fm.put("referenceUrl", f.referenceUrl);
            findings.add(fm);
        }
        m.put("findings", findings);

        List<Object> tech = new ArrayList<>();
        for (TechFinding t : result.techFindings) {
            Map<String, Object> tm = new LinkedHashMap<>();
            tm.put("product", t.product);
            tm.put("version", t.version);
            tm.put("sourceHeader", t.sourceHeader);
            tm.put("rawValue", t.rawValue);
            tech.add(tm);
        }
        m.put("techFindings", tech);
        return JsonUtil.write(m);
    }

    // Self-defensive on purpose, not just relying on loadInto()'s own per-row try/catch: this
    // reads persisted state that could be corrupted by a manually-edited project file, a future
    // format change, or disk corruption, and must degrade to "skip this one row" rather than
    // propagate a parse exception, the same standard JsonUtil.parse() failing outright doesn't meet.
    @SuppressWarnings("unchecked")
    UrlAnalysisResult fromJson(String json) {
        try {
            return fromJsonUnchecked(json);
        } catch (Exception ex) {
            return null;
        }
    }

    private UrlAnalysisResult fromJsonUnchecked(String json) {
        Object parsed = JsonUtil.parse(json);
        if (!(parsed instanceof Map<?, ?> raw)) return null;
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) raw;

        Map<String, String> rawHeaders = new LinkedHashMap<>();
        Object rh = m.get("rawHeaders");
        if (rh instanceof Map<?, ?> rhMap) {
            for (Map.Entry<?, ?> e : rhMap.entrySet()) {
                rawHeaders.put(String.valueOf(e.getKey()), e.getValue() == null ? null : String.valueOf(e.getValue()));
            }
        }

        List<HeaderFinding> findings = new ArrayList<>();
        for (Map<String, Object> fm : JsonUtil.objectList(m.get("findings"))) {
            findings.add(new HeaderFinding(
                    str(fm, "issueName"), str(fm, "headerName"), str(fm, "headerValue"),
                    str(fm, "description"), str(fm, "evidence"),
                    Severity.valueOf(str(fm, "severity")), Confidence.valueOf(str(fm, "confidence")),
                    HeaderFinding.Category.valueOf(str(fm, "category")), str(fm, "referenceUrl")));
        }

        List<TechFinding> techFindings = new ArrayList<>();
        for (Map<String, Object> tm : JsonUtil.objectList(m.get("techFindings"))) {
            techFindings.add(new TechFinding(str(tm, "product"), str(tm, "version"),
                    str(tm, "sourceHeader"), str(tm, "rawValue")));
        }

        String url  = str(m, "url");
        String host = str(m, "host");
        String path = str(m, "path");
        LocalDateTime timestamp;
        try {
            timestamp = LocalDateTime.parse(str(m, "timestamp"));
        } catch (Exception ex) {
            timestamp = LocalDateTime.now();
        }
        UrlAnalysisResult result = new UrlAnalysisResult(url, host, path, findings, rawHeaders, techFindings, timestamp);
        result.method        = str(m, "method");
        result.statusCode    = intOf(m.get("statusCode"), -1);
        result.contentLength = intOf(m.get("contentLength"), -1);
        result.probeLabel    = str(m, "probeLabel");
        return result;
    }

    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : String.valueOf(v);
    }

    private static int intOf(Object v, int def) {
        if (v instanceof Number n) return n.intValue();
        return def;
    }
}
