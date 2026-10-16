package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.DomainData;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.TechFinding;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.persistence.ExternalEvidenceArchive;
import com.b3xal.headeranalyzer.util.JsonUtil;
import com.b3xal.headeranalyzer.util.SafeLogging;

import java.time.LocalDateTime;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

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
    // Native Montoya persistence has non-trivial object overhead. Count each captured byte twice
    // and stop at 500 MiB, leaving substantial headroom below Burp's ~1 GiB object limit.
    private static final long MAX_PERSISTED_EVIDENCE_BYTES = 500L * 1024 * 1024;
    private static final int MAX_ARCHIVED_REQUEST_CHARS = 4_096;
    private static final int MAX_ARCHIVED_RESPONSE_CHARS = 12_288;

    private final PersistedObject persistence; // may be null (persistence unavailable / tests)
    private final MontoyaApi api;              // may be null in tests, used for logging only
    private final QuimeraSettings settings;    // may be null in legacy/unit-test construction
    private final String projectId;
    private final ExternalEvidenceArchive externalEvidenceArchive = new ExternalEvidenceArchive();
    // A disconnected or full archive can affect thousands of findings. Report its state once,
    // not once per response, while retaining the normal in-project fallback for every result.
    private final AtomicReference<String> lastExternalArchiveFailure = new AtomicReference<>();
    // Clear invalidates any in-flight background archive warm-up before it can continue touching
    // evidence the analyst explicitly asked to remove.
    private final AtomicLong externalArchiveGeneration = new AtomicLong();
    private static final long MAX_WARM_EVIDENCE_BYTES = 16L * 1024 * 1024;
    // host + " " + finding.aggregationKey() -> how many rows carrying that finding type have
    // been persisted so far. Primed from whatever was already on disk in loadInto(), so the cap is
    // respected across restarts too, not just within one running session.
    private final ConcurrentHashMap<String, AtomicInteger> persistedCounts = new ConcurrentHashMap<>();
    private final AtomicLong persistedEvidenceBytes = new AtomicLong();
    // A row is often persisted twice (fast headers, then the asynchronous leak result). Track
    // its current retained exchange so enriching it never spends the global budget twice.
    private final ConcurrentHashMap<String, Long> persistedEvidenceByRow = new ConcurrentHashMap<>();
    // The matching metadata is kept only for rows that currently retain a full exchange.  It lets
    // us rotate a redundant full exchange into its compact evidence excerpt when the global cap
    // is full, rather than making every later finding permanently metadata-only.
    private final ConcurrentHashMap<String, UrlAnalysisResult> persistedEvidenceResults = new ConcurrentHashMap<>();

    public ResultStore(PersistedObject persistence, MontoyaApi api) {
        this(persistence, api, null, "unknown-project");
    }

    public ResultStore(PersistedObject persistence, MontoyaApi api, QuimeraSettings settings, String projectId) {
        this.persistence = persistence;
        this.api         = api;
        this.settings    = settings;
        this.projectId   = projectId == null || projectId.isBlank() ? "unknown-project" : projectId;
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
                        if (result == null || result.findings.isEmpty()) continue;
                        dd.addResult(result);
                        // Only a row that actually carried the (expensive, quota-capped) exchange
                        // consumed quota when it was first persisted, a metadata-only row didn't.
                        if (result.originalRequest != null) {
                            for (HeaderFinding f : result.findings) countKey(host, f).incrementAndGet();
                            persistedEvidenceBytes.addAndGet(estimateEvidenceBytes(result));
                            persistedEvidenceByRow.put(rowId(host, result.rowKey()), estimateEvidenceBytes(result));
                            persistedEvidenceResults.put(rowId(host, result.rowKey()), result);
                        }
                        loaded++;
                    } catch (Exception rowEx) {
                        // One corrupted row must not sink every other persisted finding.
                        SafeLogging.error(api, "[Quimera] failed to restore persisted result "
                                + host + " " + rowKey + ": " + rowEx.getMessage());
                    }
                }
            }
        } catch (Exception ex) {
            SafeLogging.error(api, "[Quimera] failed to load persisted results: " + ex.getMessage());
        }
    }

    /** Called from the Logger's "Clear" action: persisted findings must actually go away, not
     * silently reappear the next time the project is reopened because only the in-memory
     * domainStore was wiped. */
    public void clearAll() {
        externalArchiveGeneration.incrementAndGet();
        externalEvidenceArchive.clearMemoryCache();
        persistedCounts.clear();
        persistedEvidenceBytes.set(0);
        persistedEvidenceByRow.clear();
        persistedEvidenceResults.clear();
        if (persistence != null) {
            try {
                persistence.deleteChildObject(ROOT_KEY);
            } catch (Exception ex) {
                SafeLogging.error(api, "[Quimera] failed to clear persisted results: " + ex.getMessage());
            }
        }
        clearExternalEvidenceArchive();
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
    public synchronized void persist(UrlAnalysisResult result) {
        if (persistence == null || result.findings.isEmpty()) return;
        boolean hasExchange = result.originalRequest != null && result.originalResponse != null;
        String rowId = rowId(result.host, result.rowKey());
        long priorEvidence = persistedEvidenceByRow.getOrDefault(rowId, 0L);
        boolean reservedNow = false;
        List<EvictedEvidence> evicted = List.of();
        try {
            PersistedObject root = persistence.getChildObject(ROOT_KEY);
            if (root == null) root = PersistedObject.persistedObject();
            boolean externallyArchived = hasExchange && archiveExternally(result);
            boolean includeExchange = !externallyArchived && hasExchange && priorEvidence > 0;
            // A verified external object is the complete evidence for this row. Do not then
            // spend the native project quota on a second full copy; metadata and excerpts below
            // remain in the project as the offline/disconnected-archive fallback.
            if (!externallyArchived && !includeExchange && hasExchange && hasQuotaRemaining(result)) {
                reservedNow = reserveEvidenceBudget(result);
                if (!reservedNow) {
                    // Full persistence must remain a rolling cache, not a one-way door: compact an
                    // older redundant row first, then admit the newly observed exchange. Findings
                    // themselves are never removed; only their reopenable full messages rotate out.
                    evicted = evictEvidenceUntilFits(root, rowId, estimateEvidenceBytes(result));
                    reservedNow = reserveEvidenceBudget(result);
                }
                includeExchange = reservedNow;
            }
            if (!includeExchange && hasExchange) archiveEvidence(result);
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
            if (includeExchange && priorEvidence == 0) {
                for (HeaderFinding f : result.findings) countKey(result.host, f).incrementAndGet();
            }
            if (includeExchange) {
                persistedEvidenceByRow.put(rowId, estimateEvidenceBytes(result));
                persistedEvidenceResults.put(rowId, result);
            }
            else if (priorEvidence > 0) {
                persistedEvidenceByRow.remove(rowId);
                persistedEvidenceResults.remove(rowId);
                persistedEvidenceBytes.addAndGet(-priorEvidence);
            }
        } catch (Exception ex) {
            if (reservedNow) persistedEvidenceBytes.addAndGet(-estimateEvidenceBytes(result));
            restoreEvictedEvidence(evicted);
            // Never let a persistence hiccup break live analysis, same posture as RuleStore.save().
            SafeLogging.error(api, "[Quimera] failed to persist result for " + result.url + ": " + ex.getMessage());
        }
    }

    /**
     * Loads one selected external exchange on demand. Startup deliberately never calls this: a
     * large archive must not turn project opening into a full disk scan. Returns a safe, concise
     * status message on failure so callers can show it instead of silently falling back to an
     * unrelated request/response.
     */
    public String loadExternalEvidence(UrlAnalysisResult result) {
        if (result == null || result.externalEvidenceReference == null) return "No external evidence is attached to this finding.";
        Path directory = externalProjectDirectory();
        if (directory == null) return "External evidence archive is not configured or is disconnected.";
        try {
            ExternalEvidenceArchive.Evidence evidence = externalEvidenceArchive.read(directory,
                    result.externalEvidenceReference);
            restoreExchange(result, evidence);
            if (!result.externalProbeEvidenceReferences.isEmpty()) {
                List<HttpRequestResponse> probes = new ArrayList<>();
                for (ExternalEvidenceArchive.ArchiveReference probeReference : result.externalProbeEvidenceReferences) {
                    ExternalEvidenceArchive.Evidence probe = externalEvidenceArchive.read(directory, probeReference);
                    HttpService probeService = HttpService.httpService(probe.serviceHost(), probe.servicePort(), probe.secure());
                    probes.add(HttpRequestResponse.httpRequestResponse(
                            HttpRequest.httpRequest(probeService, ByteArray.byteArray(probe.requestBytes())),
                            HttpResponse.httpResponse(ByteArray.byteArray(probe.responseBytes()))));
                }
                result.probeExchanges = List.copyOf(probes);
            }
            return null;
        } catch (Exception ex) {
            SafeLogging.error(api, "[Quimera] external evidence unavailable for " + result.url + ": " + ex.getMessage());
            return "External evidence could not be loaded: " + conciseArchiveError(ex);
        }
    }

    /**
     * Slowly verifies and warms archived evidence after the UI is already available. It never
     * attaches every response to result rows (which would recreate the unbounded-memory problem
     * the external archive solves); {@link ExternalEvidenceArchive}'s bounded decoded LRU makes
     * recently warmed rows fast, and selecting any other row transparently loads it on demand.
     *
     * <p>The caller owns scheduling. This method performs no Swing work and must run on exactly
     * one background worker. Oversized exchanges stay on disk until selected, so a single unusual
     * response cannot create a large allocation during project opening.</p>
     */
    public void warmExternalEvidence(ConcurrentHashMap<String, DomainData> domainStore,
                                     BooleanSupplier shouldContinue) {
        if (domainStore == null || settings == null || !settings.isExternalEvidenceArchiveEnabled()) return;
        Path directory = externalProjectDirectory();
        if (directory == null) return;
        long generation = externalArchiveGeneration.get();
        java.util.HashSet<String> warmed = new java.util.HashSet<>();
        for (DomainData domain : domainStore.values()) {
            for (UrlAnalysisResult result : domain.getUrlResults().values()) {
                if (!canContinueWarmup(shouldContinue, generation)) return;
                warmReference(directory, result.externalEvidenceReference, warmed, shouldContinue, generation);
                for (ExternalEvidenceArchive.ArchiveReference probe : result.externalProbeEvidenceReferences) {
                    if (!canContinueWarmup(shouldContinue, generation)) return;
                    warmReference(directory, probe, warmed, shouldContinue, generation);
                }
            }
        }
    }

    private void warmReference(Path directory, ExternalEvidenceArchive.ArchiveReference reference,
                               java.util.Set<String> warmed, BooleanSupplier shouldContinue, long generation) {
        if (reference == null || !warmed.add(reference.objectId())) return;
        // Leave a very large object safely on disk. Selection still loads it automatically; this
        // is only the low-priority reopen warm-up path.
        if (reference.uncompressedBytes() > MAX_WARM_EVIDENCE_BYTES) return;
        try {
            externalEvidenceArchive.read(directory, reference);
            // Deliberately modest I/O pacing. A project can keep opening and Burp can keep
            // handling traffic while evidence becomes warm in the background.
            Thread.sleep(15);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (Exception ex) {
            noteExternalArchiveFailure("warm-up", conciseArchiveError(ex));
        }
    }

    private boolean canContinueWarmup(BooleanSupplier shouldContinue, long generation) {
        return !Thread.currentThread().isInterrupted()
                && externalArchiveGeneration.get() == generation
                && (shouldContinue == null || shouldContinue.getAsBoolean());
    }

    private boolean archiveExternally(UrlAnalysisResult result) {
        Path directory = externalProjectDirectory();
        if (directory == null) return false;
        try {
            ExternalEvidenceArchive.ArchiveReference original = archiveExchange(directory, result.rowKey(),
                    result.url, result.originalRequest, result.originalResponse);
            List<ExternalEvidenceArchive.ArchiveReference> probes = new ArrayList<>();
            for (int i = 0; i < result.probeExchanges.size(); i++) {
                HttpRequestResponse probe = result.probeExchanges.get(i);
                if (probe == null || probe.request() == null || probe.response() == null) {
                    throw new IllegalStateException("probe evidence is incomplete");
                }
                probes.add(archiveExchange(directory, result.rowKey() + "|probe|" + i, probe.request().url(),
                        probe.request(), probe.response()));
            }
            // Only attach references after every part is durably written. If an individual probe
            // cannot be archived, ResultStore keeps the whole native evidence set as fallback.
            result.externalEvidenceReference = original;
            result.externalProbeEvidenceReferences = List.copyOf(probes);
            lastExternalArchiveFailure.set(null);
            return true;
        } catch (Exception ex) {
            // Do not claim success and do not drop into metadata-only mode: the existing bounded
            // Burp-project persistence remains the proven fallback for this exact result.
            noteExternalArchiveFailure("write", conciseArchiveError(ex));
            return false;
        }
    }

    private ExternalEvidenceArchive.ArchiveReference archiveExchange(Path directory, String resultId, String url,
                                                                       HttpRequest request, HttpResponse response)
            throws java.io.IOException {
        HttpService service = request.httpService();
        if (service == null) throw new IllegalStateException("request has no HTTP service");
        ExternalEvidenceArchive.Evidence evidence = new ExternalEvidenceArchive.Evidence(
                projectId, resultId, url, service.host(), service.port(), service.secure(),
                request.toByteArray().getBytes(), response.toByteArray().getBytes());
        return externalEvidenceArchive.write(directory, evidence);
    }

    private static void restoreExchange(UrlAnalysisResult result, ExternalEvidenceArchive.Evidence evidence) {
        HttpService service = HttpService.httpService(evidence.serviceHost(), evidence.servicePort(), evidence.secure());
        result.originalRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(evidence.requestBytes()));
        result.originalResponse = HttpResponse.httpResponse(ByteArray.byteArray(evidence.responseBytes()));
        result.rawRequest = result.originalRequest.toString();
        result.rawResponse = result.originalResponse.toString();
    }

    private Path externalProjectDirectory() {
        if (settings == null || !settings.isExternalEvidenceArchiveEnabled()) return null;
        String configured = settings.getExternalEvidenceArchiveDirectory();
        if (configured == null || configured.isBlank()) {
            noteExternalArchiveFailure("configuration", "no folder is configured");
            return null;
        }
        return configuredExternalProjectDirectory();
    }

    /** Returns only Quimera's project-specific child directory, never the user-selected root.
     * Clear may call this even if archive writes are currently disabled: disabled configuration
     * must not leave previous evidence behind when the analyst explicitly clears the project. */
    private Path configuredExternalProjectDirectory() {
        if (settings == null) return null;
        String configured = settings.getExternalEvidenceArchiveDirectory();
        if (configured == null || configured.isBlank()) return null;
        try {
            return Path.of(configured).toAbsolutePath().normalize()
                    .resolve("quimera-evidence").resolve(projectDirectoryId());
        } catch (RuntimeException badPath) {
            if (settings.isExternalEvidenceArchiveEnabled()) {
                noteExternalArchiveFailure("configuration", conciseArchiveError(badPath));
            }
            return null;
        }
    }

    /**
     * Removes only the content-addressed archive directory belonging to this exact Burp project.
     * The caller has already obtained Clear's explicit destructive-action confirmation. Do not
     * delete the user-selected archive root or its {@code quimera-evidence} parent: either may
     * contain archives for other projects or arbitrary user files.
     */
    private void clearExternalEvidenceArchive() {
        Path projectDirectory = configuredExternalProjectDirectory();
        if (projectDirectory == null || !Files.exists(projectDirectory, LinkOption.NOFOLLOW_LINKS)) return;
        // A project directory symlink would make recursive deletion ambiguous. Refuse safely
        // rather than following it outside the archive tree.
        if (!Files.isDirectory(projectDirectory, LinkOption.NOFOLLOW_LINKS)) {
            SafeLogging.error(api, "[Quimera] external evidence archive clear skipped: project archive is not a directory");
            return;
        }
        try {
            Files.walkFileTree(projectDirectory, new SimpleFileVisitor<>() {
                @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override public FileVisitResult postVisitDirectory(Path directory, IOException failure) throws IOException {
                    if (failure != null) throw failure;
                    Files.delete(directory);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException ex) {
            // Findings are already cleared from the project; make residual sensitive evidence
            // explicit rather than presenting a false impression that Clear removed it.
            SafeLogging.error(api, "[Quimera] failed to clear external evidence archive for this project: "
                    + conciseArchiveError(ex));
        }
    }

    private String projectDirectoryId() {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(projectId.getBytes(java.nio.charset.StandardCharsets.UTF_8))).substring(0, 32);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is required by the JRE", impossible);
        }
    }

    private static String conciseArchiveError(Exception ex) {
        String message = ex.getMessage();
        return message == null || message.isBlank() ? ex.getClass().getSimpleName() : message;
    }

    private void noteExternalArchiveFailure(String operation, String detail) {
        String state = operation + ": " + detail;
        if (state.equals(lastExternalArchiveFailure.getAndSet(state))) return;
        SafeLogging.error(api, "[Quimera] external evidence archive " + operation
                + " failed; retaining project evidence instead: " + detail);
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

    private boolean reserveEvidenceBudget(UrlAnalysisResult result) {
        long estimate = estimateEvidenceBytes(result);
        while (true) {
            long used = persistedEvidenceBytes.get();
            if (estimate > MAX_PERSISTED_EVIDENCE_BYTES - used) return false;
            if (persistedEvidenceBytes.compareAndSet(used, used + estimate)) return true;
        }
    }

    /**
     * Makes space only by rotating persisted exchanges into compact excerpts. Prefer a row for
     * which every finding type still has another full example; when that cannot free enough, use
     * the least severe/oldest retained row. This gives newly observed evidence a chance to survive
     * while preserving both the finding and an evidence excerpt for every evicted row.
     */
    private List<EvictedEvidence> evictEvidenceUntilFits(PersistedObject root, String protectedRowId, long neededBytes) {
        if (neededBytes > MAX_PERSISTED_EVIDENCE_BYTES) return List.of();
        List<EvictedEvidence> evicted = new ArrayList<>();
        while (neededBytes > MAX_PERSISTED_EVIDENCE_BYTES - persistedEvidenceBytes.get()) {
            String victimId = chooseEvictionCandidate(protectedRowId, true);
            if (victimId == null) victimId = chooseEvictionCandidate(protectedRowId, false);
            if (victimId == null) return evicted;
            UrlAnalysisResult victim = persistedEvidenceResults.get(victimId);
            Long bytes = persistedEvidenceByRow.get(victimId);
            if (victim == null || bytes == null) {
                persistedEvidenceResults.remove(victimId);
                persistedEvidenceByRow.remove(victimId);
                continue;
            }
            archiveEvidence(victim);
            PersistedObject hostObj = root.getChildObject(victim.host);
            if (hostObj == null) return evicted; // retain accounting; do not make a false space claim
            hostObj.setChildObject(victim.rowKey(), buildRow(victim, false));
            root.setChildObject(victim.host, hostObj);
            persistedEvidenceResults.remove(victimId);
            persistedEvidenceByRow.remove(victimId);
            persistedEvidenceBytes.addAndGet(-bytes);
            for (HeaderFinding finding : victim.findings) {
                AtomicInteger count = countKey(victim.host, finding);
                count.updateAndGet(value -> Math.max(0, value - 1));
            }
            evicted.add(new EvictedEvidence(victimId, victim, bytes));
        }
        return evicted;
    }

    private void restoreEvictedEvidence(List<EvictedEvidence> evicted) {
        for (EvictedEvidence item : evicted) {
            persistedEvidenceByRow.put(item.rowId(), item.bytes());
            persistedEvidenceResults.put(item.rowId(), item.result());
            persistedEvidenceBytes.addAndGet(item.bytes());
            for (HeaderFinding finding : item.result().findings) countKey(item.result().host, finding).incrementAndGet();
        }
    }

    private record EvictedEvidence(String rowId, UrlAnalysisResult result, long bytes) { }

    private String chooseEvictionCandidate(String protectedRowId, boolean redundantOnly) {
        String selected = null;
        for (Map.Entry<String, UrlAnalysisResult> entry : persistedEvidenceResults.entrySet()) {
            String id = entry.getKey();
            UrlAnalysisResult candidate = entry.getValue();
            if (id.equals(protectedRowId) || !persistedEvidenceByRow.containsKey(id)
                    || (redundantOnly && !hasAnotherFullExampleForEveryFinding(candidate))) continue;
            if (selected == null || compareEvictionPriority(candidate, persistedEvidenceResults.get(selected)) < 0) {
                selected = id;
            }
        }
        return selected;
    }

    private boolean hasAnotherFullExampleForEveryFinding(UrlAnalysisResult result) {
        for (HeaderFinding finding : result.findings) {
            if (countKey(result.host, finding).get() <= 1) return false;
        }
        return true;
    }

    /** Lowest severity first; equal severity falls back to the oldest observation. */
    private static int compareEvictionPriority(UrlAnalysisResult left, UrlAnalysisResult right) {
        int leftSeverity = left.findings.stream().mapToInt(f -> f.severity.order).max().orElse(0);
        int rightSeverity = right.findings.stream().mapToInt(f -> f.severity.order).max().orElse(0);
        int bySeverity = Integer.compare(leftSeverity, rightSeverity);
        return bySeverity != 0 ? bySeverity : left.timestamp.compareTo(right.timestamp);
    }

    private static long estimateEvidenceBytes(UrlAnalysisResult result) {
        try {
            long raw = result.originalRequest.toString().length() + result.originalResponse.toString().length();
            return Math.max(8_192, raw * 2L + 4_096);
        } catch (Exception ex) { return 8_192; }
    }

    private static void archiveEvidence(UrlAnalysisResult result) {
        if (result.archivedRequestExcerpt != null || result.originalRequest == null || result.originalResponse == null) return;
        result.archivedRequestExcerpt = excerpt(result.originalRequest.toString(), MAX_ARCHIVED_REQUEST_CHARS, null);
        List<String> needles = result.findings.stream().map(f -> f.headerValue)
                .filter(v -> v != null && !v.isBlank()).distinct().limit(8).toList();
        result.archivedResponseExcerpt = excerptAll(result.originalResponse.toString(), MAX_ARCHIVED_RESPONSE_CHARS, needles);
    }

    private static String excerpt(String raw, int max, String needle) {
        if (raw == null || raw.length() <= max) return raw;
        int at = needle == null ? -1 : raw.indexOf(needle);
        if (at < 0) return raw.substring(0, max) + "\n[archived evidence truncated]";
        int start = Math.max(0, at - max / 3);
        int end = Math.min(raw.length(), start + max);
        return (start > 0 ? "[archived evidence truncated]\n" : "") + raw.substring(start, end)
                + (end < raw.length() ? "\n[archived evidence truncated]" : "");
    }

    /** Keeps evidence for every distinct finding, not merely the first match in a large error page. */
    static String excerptAll(String raw, int max, List<String> needles) {
        if (raw == null || raw.length() <= max || needles.isEmpty()) return excerpt(raw, max, null);
        StringBuilder out = new StringBuilder();
        int headerEnd = raw.indexOf("\r\n\r\n");
        if (headerEnd < 0) headerEnd = raw.indexOf("\n\n");
        if (headerEnd >= 0) out.append(raw, 0, Math.min(headerEnd + 4, Math.min(raw.length(), 2048))).append("\n[body excerpts]\n");
        int each = Math.max(768, (max - out.length()) / needles.size());
        java.util.HashSet<Integer> seen = new java.util.HashSet<>();
        for (String needle : needles) {
            int at = raw.indexOf(needle);
            if (at < 0 || !seen.add(at)) continue;
            int start = Math.max(0, at - each / 3);
            int end = Math.min(raw.length(), start + each);
            if (!out.isEmpty()) out.append("\n--- evidence excerpt: ").append(needle).append(" ---\n");
            out.append(start > 0 ? "[truncated]\n" : "").append(raw, start, end)
                    .append(end < raw.length() ? "\n[truncated]" : "");
        }
        return out.length() > max ? out.substring(0, max) + "\n[archived evidence truncated]" : out.toString();
    }

    AtomicInteger countKey(String host, HeaderFinding finding) {
        return persistedCounts.computeIfAbsent(host + " " + finding.aggregationKey(),
                ignored -> new AtomicInteger());
    }

    private static String rowId(String host, String rowKey) { return host + "\u0000" + rowKey; }

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
        m.put("archivedRequestExcerpt", result.archivedRequestExcerpt);
        m.put("archivedResponseExcerpt", result.archivedResponseExcerpt);
        if (result.externalEvidenceReference != null) {
            m.put("externalEvidenceObjectId", result.externalEvidenceReference.objectId());
            m.put("externalEvidenceBytes", result.externalEvidenceReference.uncompressedBytes());
        }
        if (!result.externalProbeEvidenceReferences.isEmpty()) {
            List<Object> externalProbes = new ArrayList<>();
            for (ExternalEvidenceArchive.ArchiveReference reference : result.externalProbeEvidenceReferences) {
                Map<String, Object> probe = new LinkedHashMap<>();
                probe.put("objectId", reference.objectId());
                probe.put("bytes", reference.uncompressedBytes());
                externalProbes.add(probe);
            }
            m.put("externalProbeEvidence", externalProbes);
        }
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
            fm.put("userDefinedRule", f.userDefinedRule);
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
            HeaderFinding finding = new HeaderFinding(
                    str(fm, "issueName"), str(fm, "headerName"), str(fm, "headerValue"),
                    str(fm, "description"), str(fm, "evidence"),
                    Severity.valueOf(str(fm, "severity")), Confidence.valueOf(str(fm, "confidence")),
                    HeaderFinding.Category.valueOf(str(fm, "category")), str(fm, "referenceUrl"), Boolean.TRUE.equals(fm.get("userDefinedRule")));
            if (!retiredBuiltinNoise(finding)) findings.add(finding);
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
        result.archivedRequestExcerpt = str(m, "archivedRequestExcerpt");
        result.archivedResponseExcerpt = str(m, "archivedResponseExcerpt");
        String externalObjectId = str(m, "externalEvidenceObjectId");
        if (externalObjectId != null) {
            try {
                result.externalEvidenceReference = new ExternalEvidenceArchive.ArchiveReference(
                        externalObjectId, longOf(m.get("externalEvidenceBytes"), -1));
            } catch (IllegalArgumentException ignored) {
                // A manually damaged project row must not make the whole finding disappear.
            }
        }
        List<ExternalEvidenceArchive.ArchiveReference> externalProbes = new ArrayList<>();
        for (Map<String, Object> probe : JsonUtil.objectList(m.get("externalProbeEvidence"))) {
            try {
                externalProbes.add(new ExternalEvidenceArchive.ArchiveReference(
                        str(probe, "objectId"), longOf(probe.get("bytes"), -1)));
            } catch (IllegalArgumentException ignored) {
                // Keep valid siblings; one damaged optional probe reference must not discard the row.
            }
        }
        result.externalProbeEvidenceReferences = List.copyOf(externalProbes);
        return result;
    }

    /** Rules retired because they merely duplicated Technology/cache telemetry must not reappear
     * from older project persistence. Match only their former exact built-in titles, preserving
     * similarly named user-defined rules and every other historical finding. */
    private static boolean retiredBuiltinNoise(HeaderFinding finding) {
        if (finding.userDefinedRule || finding.issueName == null) return false;
        // A blank Server value identifies no product or version. Older releases could persist a
        // generic family-disclosure result because their regex also matched the empty string.
        // Suppress only that impossible built-in result; real named Server disclosures remain.
        if ("Server technology family disclosure".equals(finding.issueName)
                && "Server".equalsIgnoreCase(finding.headerName)
                && (finding.headerValue == null || finding.headerValue.isBlank())) return true;
        return switch (finding.issueName) {
            case "Server-Timing header present",
                 "Resource timing access policy observed",
                 "Varnish family disclosure via transaction ID header",
                 "Upstream timing metadata observed",
                 "Cache infrastructure disclosure",
                 "Cache hit count disclosure",
                 "Cache status disclosure",
                 "Shared HTTP cache activity detected",
                 "Same authentication credential observed in multiple locations",
                 "Authentication mechanism value changed during capture",
                 "Pingback endpoint advertised" -> true;
            default -> false;
        };
    }

    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : String.valueOf(v);
    }

    private static int intOf(Object v, int def) {
        if (v instanceof Number n) return n.intValue();
        return def;
    }

    private static long longOf(Object v, long def) {
        if (v instanceof Number n) return n.longValue();
        try { return v == null ? def : Long.parseLong(String.valueOf(v)); }
        catch (NumberFormatException ignored) { return def; }
    }
}
