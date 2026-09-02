package com.b3xal.headeranalyzer.ui;

import com.b3xal.headeranalyzer.analyzer.CookieAnalyzer;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.ui.render.SeverityRenderer;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.*;

/**
 * Cookies & Auth get their own tab instead of being mixed into the Headers Logger's issue list,
 * because these findings aren't "one issue affecting a header", they're a per-cookie/per-token
 * INVENTORY (Secure/HttpOnly/SameSite/prefix compliance for cookies; JWT/HTTP-Basic/Bearer/API-key
 * recognition for tokens, see JwtAnalyzer/AuthHeaderAnalyzer), grouped by cookie NAME or token
 * identity rather than by issue.
 *
 * Two group families share one table, distinguished by the "Kind" column: cookie groups (Kind =
 * "Cookie", keyed by cookie NAME, a String) inventory every cookie seen per host, even fully
 * compliant ones, the same way TechFingerprinter's inventory isn't filtered down to only problems.
 * Auth-token groups (Kind = "JWT"/"Basic Auth"/"Bearer"/"API Key"/"URL Token", keyed by an
 * {@link AuthKey}) inventory distinct tokens observed, grouped by VALUE rather than name (a
 * rotated/refreshed token is a new group, deliberately, that's meaningful for a token in a way it
 * isn't for a cookie's flags), since Category.AUTH findings always carry at least one finding when
 * a token is recognized, there's no "fully compliant, zero-finding" case to inventory the way a
 * cookie can be.
 *
 * Mirrors LoggerPanel's incremental-update architecture (never wholesale-rebuilds the tables on
 * live traffic, only surgical addRow/setValueAt/removeRow so selection survives).
 */
public final class CookiePanel extends JPanel {

    private static class CookieGroup {
        final String host, cookieName;
        Severity severity = Severity.INFORMATION;
        String flagsSummary = "";
        HeaderFinding representative; // worst finding for this cookie, null when fully compliant
        final LinkedHashMap<String, UrlAnalysisResult> affected = new LinkedHashMap<>();

        CookieGroup(String host, String cookieName) {
            this.host = host;
            this.cookieName = cookieName;
        }
    }

    /** Identity of one distinct auth token: which host, which header carried it (Authorization,
     * Cookie, Set-Cookie, X-Api-Key, ..., or "(URL query string)"), and its exact value, so a
     * rotated/refreshed token becomes its own group instead of silently merging into the old one. */
    private record AuthKey(String host, String headerName, String value) {}

    private static class AuthGroup {
        final AuthKey key;
        final String host, headerName, kind;
        String displayName;
        final boolean requestSide;
        Severity severity = Severity.INFORMATION;
        String claimsSummary = "";
        HeaderFinding representative;
        final LinkedHashMap<String, UrlAnalysisResult> affected = new LinkedHashMap<>();

        AuthGroup(AuthKey key, String kind) {
            this.key = key;
            this.host = key.host();
            this.headerName = key.headerName();
            this.kind = kind;
            this.requestSide = !headerName.equalsIgnoreCase("Set-Cookie")
                    && !headerName.equalsIgnoreCase("(response body)")
                    // Static WebStorageAnalyzer findings are extracted from response JavaScript.
                    && !headerName.equalsIgnoreCase("(Web Storage)")
                    // Every browser-bridge location is rendered in BrowserEvidence's synthetic
                    // JSON response, never in its placeholder request. This includes Web Storage,
                    // window globals and browser cookies, including future "(Browser: ...)"
                    // sources without needing another one-off exception here.
                    && !headerName.regionMatches(true, 0, "(Browser:", 0, "(Browser:".length());
            this.displayName = headerName + ": " + truncate(key.value(), 28);
        }
    }

    private record ParsedCookie(String name, String raw, List<String> attrs) {}

    /** (result, headerName, issueNameHint, isRequestHeader): headerName is which header the
     * Detail panel should highlight, issueNameHint is the exact issue title of the currently
     * selected group's representative finding (so the Advisory pane shows THAT finding, not
     * whichever one happens to be worst on the underlying response, see the bug this fixed:
     * clicking an INFORMATION-severity row was showing a MEDIUM finding's Advisory content
     * because a null hint falls back to "worst on this response", and a JWT's several checks
     * (JWT detected/no-exp/lifetime/...) all share the same UrlAnalysisResult), isRequestHeader
     * tells it whether to search the request or response editor (a JWT in Authorization/Cookie is
     * request-side, one in Set-Cookie is response-side, same as a plain cookie's flags always
     * are). */
    @FunctionalInterface
    public interface CookieRowSelectionListener {
        void onSelect(UrlAnalysisResult result, String headerName, String issueNameHint, boolean isRequestHeader);
    }

    private final Map<String, UrlAnalysisResult> rows = new LinkedHashMap<>();
    private final Map<String, CookieGroup> cookieGroups = new LinkedHashMap<>();
    private final Map<AuthKey, AuthGroup> authGroups = new LinkedHashMap<>();

    private Object selectedGroupKey; // a String (cookie) or an AuthKey (auth token)
    private String selectedAffectedKey;

    private static final String[] COOKIE_COLS = {"Severity", "Kind", "Name", "Host", "Flags / Claims", "Requests"};
    private DefaultTableModel groupModel;
    private final JTable groupTable = new JTable();
    private final List<Object> groupKeysByRow = new ArrayList<>();

    private static final String[] REQ_COLS = {"Host", "Path", "Status", "Length", "Time"};
    private final DefaultTableModel reqModel = new DefaultTableModel(REQ_COLS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable reqTable = new JTable(reqModel);
    private final List<String> affectedKeysByRow = new ArrayList<>();
    private final Map<String, UrlAnalysisResult> shownAffectedByKey = new HashMap<>();
    private final JLabel affectedLabel = new JLabel("Select a row above to see the requests that carried it.");

    // Same Path/Status/Length Include/Exclude filters as LoggerPanel's affected-requests table,
    // independent of the group-table filters above (Host/Severity/Search scope WHICH cookies/
    // tokens show up top-left, these scope WHICH of that group's affected requests show up
    // bottom-right).
    private final JTextField pathFilterReq   = new JTextField(9);
    private final JTextField statusFilterReq = new JTextField(6);
    private final JTextField lengthFilterReq = new JTextField(7);
    private final JCheckBox pathExcludeToggle   = new JCheckBox("Exclude");
    private final JCheckBox statusExcludeToggle = new JCheckBox("Exclude");
    private final JCheckBox lengthExcludeToggle = new JCheckBox("Exclude");

    private final JTextField hostFilter = new JTextField(10);
    private final JTextField searchFilter = new JTextField(12);
    private final JComboBox<String> sevFilter =
            new JComboBox<>(new String[]{"All Severities", "High", "Medium", "Low", "Information"});

    private CookieRowSelectionListener onRowSelected = (r, h, i, req) -> {};

    public CookiePanel() {
        super(new BorderLayout());
        build();
    }

    public void setOnRowSelected(CookieRowSelectionListener cb) { this.onRowSelected = cb; }

    // ------ Build ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private void build() {
        groupTable.setAutoCreateRowSorter(true);
        rebuildGroupModel();

        groupTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        groupTable.setRowHeight(22);
        groupTable.setToolTipText("");
        groupTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            onGroupSelected();
        });
        groupTable.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            @Override public void mouseMoved(java.awt.event.MouseEvent e) {
                groupTable.setToolTipText(groupRowTooltip(e));
            }
        });

        reqTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        reqTable.setRowHeight(22);
        reqTable.setAutoCreateRowSorter(true);
        reqTable.setShowGrid(true);
        reqTable.setGridColor(new Color(220, 220, 220));
        reqTable.setIntercellSpacing(new Dimension(1, 1));
        reqTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = reqTable.getSelectedRow();
            if (viewRow < 0) return;
            int modelRow = reqTable.convertRowIndexToModel(viewRow);
            if (modelRow < 0 || modelRow >= affectedKeysByRow.size()) return;
            String rk = affectedKeysByRow.get(modelRow);
            UrlAnalysisResult r = shownAffectedByKey.get(rk);
            if (r != null) {
                selectedAffectedKey = rk;
                fireRowSelected(r);
            }
        });

        affectedLabel.setFont(affectedLabel.getFont().deriveFont(Font.ITALIC, 11f));
        affectedLabel.setForeground(Color.GRAY);
        affectedLabel.setBorder(BorderFactory.createEmptyBorder(4, 6, 0, 6));

        JPanel affectedHeader = new JPanel(new BorderLayout());
        affectedHeader.add(affectedLabel, BorderLayout.NORTH);
        affectedHeader.add(buildAffectedFilterRow(), BorderLayout.SOUTH);

        JPanel right = new JPanel(new BorderLayout());
        right.add(affectedHeader, BorderLayout.NORTH);
        right.add(new JScrollPane(reqTable), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(groupTable), right);
        split.setResizeWeight(0.5);
        SwingUtilities.invokeLater(() -> split.setDividerLocation(0.5));

        add(buildToolbar(), BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        hostFilter.getDocument().addDocumentListener(simpleListener(this::refreshFiltersNow));
        searchFilter.getDocument().addDocumentListener(simpleListener(this::refreshFiltersNow));
        sevFilter.addActionListener(e -> refreshFiltersNow());

        pathFilterReq.getDocument().addDocumentListener(simpleListener(this::onAffectedFilterFieldChanged));
        statusFilterReq.getDocument().addDocumentListener(simpleListener(this::onAffectedFilterFieldChanged));
        lengthFilterReq.getDocument().addDocumentListener(simpleListener(this::onAffectedFilterFieldChanged));
        pathExcludeToggle.addActionListener(e -> refreshAffectedFilterNow());
        statusExcludeToggle.addActionListener(e -> refreshAffectedFilterNow());
        lengthExcludeToggle.addActionListener(e -> refreshAffectedFilterNow());
    }

    private void onAffectedFilterFieldChanged() {
        refreshAffectedFilterNow();
        updateFiltersButtonLabel();
    }

    private static JPanel buildFilterGroup(String label, JTextField field, JCheckBox exclude) {
        JPanel g = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        g.add(new JLabel(label));
        g.add(field);
        g.add(exclude);
        return g;
    }

    private final JButton filtersToggleBtn = new JButton();

    /** Same "Filters ▾ (n)" popup-button treatment as LoggerPanel's affected-requests filter row,
     * see its javadoc: costs one button's worth of space when not in use instead of always
     * occupying a row that has to wrap/clip as the pane narrows. */
    private JPanel buildAffectedFilterRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        p.setBorder(BorderFactory.createEmptyBorder(0, 4, 4, 4));

        JPopupMenu popup = buildAffectedFilterPopup();
        filtersToggleBtn.setMargin(new Insets(1, 6, 1, 6));
        filtersToggleBtn.setToolTipText("Narrow the affected-requests table by Path/Status/Length");
        filtersToggleBtn.addActionListener(e -> popup.show(filtersToggleBtn, 0, filtersToggleBtn.getHeight()));
        updateFiltersButtonLabel();
        p.add(filtersToggleBtn);
        return p;
    }

    private JPopupMenu buildAffectedFilterPopup() {
        JPopupMenu popup = new JPopupMenu();
        popup.setLayout(new BoxLayout(popup, BoxLayout.Y_AXIS));
        String tip = "Comma-separated, e.g. \"200,301\". Check Exclude to hide matching rows " +
                "instead of keeping only them.";

        pathFilterReq.setToolTipText(tip + " Path matches by substring.");
        pathExcludeToggle.setToolTipText(tip);
        popup.add(buildFilterGroup("Path:", pathFilterReq, pathExcludeToggle));

        statusFilterReq.setToolTipText(tip + " Status matches exactly.");
        statusExcludeToggle.setToolTipText(tip);
        popup.add(buildFilterGroup("Status:", statusFilterReq, statusExcludeToggle));

        lengthFilterReq.setToolTipText(tip + " Length (bytes) matches exactly.");
        lengthExcludeToggle.setToolTipText(tip);
        popup.add(buildFilterGroup("Length:", lengthFilterReq, lengthExcludeToggle));

        JButton clearBtn = new JButton("Clear");
        clearBtn.setMargin(new Insets(1, 6, 1, 6));
        clearBtn.addActionListener(e -> {
            pathFilterReq.setText("");
            statusFilterReq.setText("");
            lengthFilterReq.setText("");
            pathExcludeToggle.setSelected(false);
            statusExcludeToggle.setSelected(false);
            lengthExcludeToggle.setSelected(false);
            refreshAffectedFilterNow();
            updateFiltersButtonLabel();
        });
        JPanel clearRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 4));
        clearRow.add(clearBtn);
        popup.add(clearRow);
        return popup;
    }

    private void updateFiltersButtonLabel() {
        int active = 0;
        if (!pathFilterReq.getText().isBlank()) active++;
        if (!statusFilterReq.getText().isBlank()) active++;
        if (!lengthFilterReq.getText().isBlank()) active++;
        filtersToggleBtn.setText(active > 0 ? "Filters ▾ (" + active + ")" : "Filters ▾");
    }

    private void refreshAffectedFilterNow() {
        if (selectedGroupKey != null) populateAffectedTableForSelectedGroup();
    }

    /** Same include/exclude token filter as LoggerPanel's. Blank filterText always passes.
     * Comma-separated values all share the field's Include/Exclude toggle state. */
    private static boolean passesValueFilter(String filterText, String actualValue, boolean substring, boolean exclude) {
        if (filterText == null || filterText.isBlank()) return true;
        String value = actualValue == null ? "" : actualValue.toLowerCase(Locale.ROOT);
        List<String> values = new ArrayList<>();
        for (String raw : filterText.split(",")) {
            String t = raw.trim().toLowerCase(Locale.ROOT);
            if (!t.isEmpty()) values.add(t);
        }
        if (values.isEmpty()) return true;
        boolean anyMatch = values.stream().anyMatch(v -> substring ? value.contains(v) : value.equals(v));
        return exclude != anyMatch;
    }

    /** Combined Host (group-table filter, reused here) + Path/Status/Length gate for whether a
     * result belongs in the affected-requests table right now. */
    private boolean passesAffectedFilters(UrlAnalysisResult r) {
        String host = hostFilter.getText().trim().toLowerCase(Locale.ROOT);
        if (!host.isEmpty() && !r.host.toLowerCase(Locale.ROOT).contains(host)) return false;
        if (!passesValueFilter(pathFilterReq.getText(), r.path, true, pathExcludeToggle.isSelected())) return false;
        if (!passesValueFilter(statusFilterReq.getText(),
                r.statusCode > 0 ? String.valueOf(r.statusCode) : "", false, statusExcludeToggle.isSelected())) return false;
        if (!passesValueFilter(lengthFilterReq.getText(),
                r.contentLength >= 0 ? String.valueOf(r.contentLength) : "", false, lengthExcludeToggle.isSelected())) return false;
        return true;
    }

    /** headerName/issueNameHint/isRequestHeader for whichever group is currently selected, so the
     * affected-row listener can tell DetailPanel the right thing regardless of cookie vs.
     * auth-token kind, and Advisory shows THIS group's specific finding rather than falling back
     * to the worst one on the shared response. */
    private void fireRowSelected(UrlAnalysisResult r) {
        if (selectedGroupKey instanceof AuthKey) {
            AuthGroup g = authGroups.get(selectedGroupKey);
            onRowSelected.onSelect(r, g != null ? g.headerName : "Authorization",
                    g != null && g.representative != null ? g.representative.issueName : null,
                    g == null || g.requestSide);
        } else {
            CookieGroup g = cookieGroups.get(selectedGroupKey);
            // headerName is NOT always the literal "Set-Cookie": ingestSessionLifecycleFindings's
            // two non-Set-Cookie-driven sources (SessionLifecycleAnalyzer, browser-bridge-forwarded
            // cookie findings) deliberately set it to the real cookie NAME instead (see that
            // method's own javadoc), and DetailPanel's match requires headerName AND issueName to
            // agree, so this has to read the representative's own headerName, not assume one.
            onRowSelected.onSelect(r,
                    g != null && g.representative != null ? g.representative.headerName : "Set-Cookie",
                    g != null && g.representative != null ? g.representative.issueName : null,
                    false);
        }
    }

    private void refreshFiltersNow() {
        refreshGroupTable();
        if (selectedGroupKey == null) return;
        int modelRow = groupKeysByRow.indexOf(selectedGroupKey);
        if (modelRow < 0) {
            selectedGroupKey = null;
            selectedAffectedKey = null;
            populateAffectedTable(List.of(), null);
        } else {
            int viewRow = groupTable.convertRowIndexToView(modelRow);
            if (viewRow >= 0) groupTable.getSelectionModel().setSelectionInterval(viewRow, viewRow);
            populateAffectedTableForSelectedGroup();
        }
    }

    private JPanel buildToolbar() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));

        JPanel left = new JPanel(new WrapLayout(FlowLayout.LEFT, 6, 4));
        left.add(new JLabel("Host:"));
        left.add(hostFilter);
        left.add(new JLabel("Severity:"));
        left.add(sevFilter);
        left.add(new JLabel("Search:"));
        left.add(searchFilter);

        JButton clearFiltersBtn = new JButton("Clear filters");
        clearFiltersBtn.addActionListener(e -> {
            hostFilter.setText("");
            searchFilter.setText("");
            sevFilter.setSelectedIndex(0);
            pathFilterReq.setText("");
            statusFilterReq.setText("");
            lengthFilterReq.setText("");
            pathExcludeToggle.setSelected(false);
            statusExcludeToggle.setSelected(false);
            lengthExcludeToggle.setSelected(false);
        });
        left.add(clearFiltersBtn);

        p.add(left, BorderLayout.CENTER);
        return p;
    }

    // ------ Ingest (incremental, never clears either table) ------------------------------------------------------------------------

    /** Must be called on the EDT (see QuimeraTab#onResultAdded). */
    public void addOrUpdateRow(UrlAnalysisResult result) {
        String key = result.host + "|" + result.rowKey();
        rows.put(key, result);

        ingestCookies(result, key);
        ingestAuthTokens(result, key);
        ingestSessionLifecycleFindings(result, key);
    }

    // SessionLifecycleAnalyzer's two checks (stale session replay, static session on repeat
    // logins), identified by issueName prefix since HeaderFinding has no dedicated "check id"
    // field. Kept here rather than in that class since matching-by-prefix is a UI-attachment
    // concern, not an analysis one.
    private static final String STALE_REPLAY_PREFIX = "Session cookie still accepted after being invalidated: ";
    private static final String STATIC_LOGIN_PREFIX = "Session cookie value is static across separate logins: ";

    /** Two kinds of Category.COOKIE finding don't correspond to a Set-Cookie occurrence in THIS
     * specific response the way every other one does, so {@link #ingestCookies}'s
     * pc.raw()-equals-headerValue match can never attach them, they'd otherwise be silently
     * invisible in this tab:
     * <ol>
     *   <li>SessionLifecycleAnalyzer's two findings (stale-replay fires on a request replaying an
     *       old value, often with no Set-Cookie in the response at all).</li>
     *   <li>Cookie findings forwarded from the browser extension's bridge ({@code probeLabel ==
     *       "browser"}, see BrowserBridgeServer#forwardCookieFindings): a JS-set cookie
     *       ({@code document.cookie = ...}) never produces a real Set-Cookie response header for
     *       Burp's proxy to see, browser.cookies is the only way to know it exists at all, so
     *       there is structurally no Set-Cookie to parse here either.</li>
     * </ol>
     * Both matched by cookie name instead, {@code headerName} is deliberately set to the real
     * cookie name (not a literal "Set-Cookie") on both kinds of finding for exactly this reason.
     * Deliberately no "removed association" handling the way ingestCookies has: a historical
     * security observation from earlier in the capture shouldn't disappear from the inventory
     * just because a later, unrelated response for the same cookie doesn't repeat it. */
    private void ingestSessionLifecycleFindings(UrlAnalysisResult result, String key) {
        boolean isBrowserBridge = "browser".equals(result.probeLabel);
        for (HeaderFinding f : result.findings) {
            if (f.category != HeaderFinding.Category.COOKIE) continue;
            boolean isSessionLifecycle = f.issueName.startsWith(STALE_REPLAY_PREFIX) || f.issueName.startsWith(STATIC_LOGIN_PREFIX);
            if (!isSessionLifecycle && !isBrowserBridge) continue;

            String cookieName = f.headerName;
            String gk = result.host + "|" + cookieName;
            CookieGroup g = cookieGroups.computeIfAbsent(gk, k -> new CookieGroup(result.host, cookieName));
            // Only upgrades, never downgrades: a later, unrelated response re-ingested through
            // ingestCookies for this same cookie name could otherwise silently overwrite this
            // with a lower severity, see that method's own worst-finding recompute.
            if (g.representative == null || f.severity.order < g.representative.severity.order) {
                g.representative = f;
                g.severity = f.severity;
            }
            g.affected.put(key, result);

            upsertGroupRow(gk, cookieRowData(g), passesFilter(g.severity, g.host, g.cookieName));
            if (Objects.equals(selectedGroupKey, gk)) {
                upsertAffectedRow(result, passesAffectedFilters(result));
            }
        }
    }

    /** Deliberately no "removed association" handling, same reasoning and same "only upgrades,
     * never downgrades" principle as {@link #ingestSessionLifecycleFindings} and LoggerPanel's
     * addOrUpdateRow: a cookie evidenced with a given set of flags on one response stays listed
     * even if a later capture of the exact same URL (a 304, a redirect, ...) doesn't happen to
     * repeat Set-Cookie, browsers don't resend it on every response, that's not the cookie
     * disappearing. */
    private void ingestCookies(UrlAnalysisResult result, String key) {
        List<ParsedCookie> parsed = parseSetCookie(rawHeader(result, "Set-Cookie"));

        for (ParsedCookie pc : parsed) {
            // Still available to TechFingerprinter/reporting, but never inventory WAF-owned
            // state as if it were an application cookie whose security flags need assessment.
            if (CookieAnalyzer.isInfrastructureCookie(pc.name())) continue;
            String gk = result.host + "|" + pc.name();
            CookieGroup g = cookieGroups.computeIfAbsent(gk, k -> new CookieGroup(result.host, pc.name()));
            g.flagsSummary = flagsSummaryFor(pc.attrs());

            HeaderFinding worst = null;
            for (HeaderFinding f : result.findings) {
                if (f.category != HeaderFinding.Category.COOKIE) continue;
                if (!pc.raw().equals(f.headerValue)) continue;
                if (worst == null || f.severity.order < worst.severity.order) worst = f;
            }
            g.representative = worst;
            g.severity = worst != null ? worst.severity : Severity.INFORMATION;
            g.affected.put(key, result);

            upsertGroupRow(gk, cookieRowData(g), passesFilter(g.severity, g.host, g.cookieName));
            if (Objects.equals(selectedGroupKey, gk)) {
                upsertAffectedRow(result, passesAffectedFilters(result));
            }
        }
    }

    /** Same "no removed association" reasoning as {@link #ingestCookies}: an auth token, once
     * evidenced carrying a given finding, stays listed even if a later response for the same URL
     * doesn't happen to repeat that Authorization/Cookie/API-key header. */
    private void ingestAuthTokens(UrlAnalysisResult result, String key) {
        // Group this response's AUTH/STORAGE findings by (headerName, headerValue), every finding
        // sharing that pair describes the same one token occurrence (JwtAnalyzer/AuthHeaderAnalyzer
        // both set headerValue to the raw token/credential value on every finding they produce for it).
        Map<AuthKey, List<HeaderFinding>> byToken = new LinkedHashMap<>();
        Map<AuthKey, String> kindByToken = new LinkedHashMap<>();
        for (HeaderFinding f : result.findings) {
            if ((f.category != HeaderFinding.Category.AUTH
                    && f.category != HeaderFinding.Category.STORAGE) || f.headerValue == null) continue;
            AuthKey ak = new AuthKey(result.host, f.headerName, f.headerValue);
            byToken.computeIfAbsent(ak, k -> new ArrayList<>()).add(f);
            kindByToken.putIfAbsent(ak, kindOf(f.issueName));
        }

        for (Map.Entry<AuthKey, List<HeaderFinding>> e : byToken.entrySet()) {
            AuthKey naturalKey = e.getKey();
            List<HeaderFinding> tokenFindings = e.getValue();

            // A token whose only findings are routine inventory notes (JWT detected, missing aud/
            // iss, ...) is indistinguishable from any OTHER equally-clean token, from an analyst's
            // perspective. Tokens that rotate/refresh (silent renew every few minutes is normal
            // for OIDC SPAs) used to each mint their own top-level row just to say "yep, still a
            // JWT", real clutter for zero extra signal. Collapse those into ONE shared row per
            // (host, header), keyed by a sentinel instead of the real value. A token with an
            // ACTUAL finding (alg:none, no-exp, lifetime-exceeds, ...) still gets its own row,
            // keyed by its real value, so that specific evidence stays intact and doesn't get
            // buried in the shared bucket.
            boolean allInformational = tokenFindings.stream().allMatch(f -> f.severity == Severity.INFORMATION);
            AuthKey gk = allInformational
                    ? new AuthKey(result.host, naturalKey.headerName(), "(informational only)")
                    : naturalKey;
            AuthGroup g = authGroups.computeIfAbsent(gk, k -> new AuthGroup(k, kindByToken.get(naturalKey)));

            HeaderFinding worst = null;
            for (HeaderFinding f : tokenFindings) {
                if (worst == null || f.severity.order < worst.severity.order) worst = f;
            }
            // Only upgrade, never downgrade (same principle as everywhere else in this file):
            // matters here specifically because the shared informational bucket accumulates
            // across MANY different token values, a later one must never silently soften whatever
            // the group already settled on.
            if (g.representative == null || (worst != null && worst.severity.order < g.representative.severity.order)) {
                g.representative = worst;
                g.severity = worst != null ? worst.severity : Severity.INFORMATION;
            }
            if (g.representative != null) g.displayName = authDisplayName(g.representative);
            g.claimsSummary = claimsSummaryFor(tokenFindings);
            g.affected.put(key, result);

            upsertGroupRow(gk, authRowData(g), passesFilter(g.severity, g.host, authSearchText(g)));
            if (Objects.equals(selectedGroupKey, gk)) {
                upsertAffectedRow(result, passesAffectedFilters(result));
            }
        }
    }

    private static String kindOf(String issueName) {
        if (issueName.startsWith("Identifying data exposed in")) return "Web Storage identifier";
        if (issueName.startsWith("JWT")) return "JWT";
        if (issueName.contains("Basic Authentication")) return "Basic Auth";
        if (issueName.contains("Bearer token")) return "Bearer";
        if (issueName.contains("embedded in client-visible response")
                || issueName.contains(" observed in response body")
                || issueName.contains(" observed in request body")) return "Secrets/Credentials";
        if (issueName.contains("API key")) return "API Key";
        if (issueName.contains("URL query string")) return "URL Token";
        return "Auth";
    }

    private static String authDisplayName(HeaderFinding finding) {
        if (finding.headerName.equalsIgnoreCase("(response body)")
                || finding.headerName.equalsIgnoreCase("(request body)")) {
            int colon = finding.issueName.lastIndexOf(':');
            String label = colon >= 0 ? finding.issueName.substring(colon + 1).trim()
                    : finding.issueName.replace(" observed in response body", "")
                            .replace(" observed in request body", "");
            return label;
        }
        return finding.headerName + ": " + truncate(finding.headerValue, 28);
    }

    /** Search auth rows with the same useful material shown in Advisory, not just their visual
     * name. Body credentials otherwise disappeared when searching for "client secret", the issue
     * title, its evidence, or its source location. */
    private static String authSearchText(AuthGroup group) {
        HeaderFinding finding = group.representative;
        if (finding == null) return group.displayName + " " + group.kind + " " + group.headerName;
        return String.join(" ", group.displayName, group.kind, group.headerName,
                finding.issueName, finding.description, finding.evidence,
                finding.headerValue != null ? finding.headerValue : "");
    }

    /** Short human summary for the "Flags / Claims" column: the algorithm + a rough expiry
     * distance for JWTs, or just the count of findings for everything else (Basic/Bearer/API-key
     * don't have claims to summarize, their one finding's issue name already says what it is). */
    private static String claimsSummaryFor(List<HeaderFinding> findings) {
        for (HeaderFinding f : findings) {
            int idx = f.description.indexOf("Technology hint: ");
            if (idx >= 0) {
                int start = idx + "Technology hint: ".length();
                int end = f.description.indexOf('.', start);
                return "Technology: " + f.description.substring(start, end >= 0 ? end : f.description.length());
            }
        }
        for (HeaderFinding f : findings) {
            if (f.issueName.startsWith("JWT detected")) {
                // description already reads "...Algorithm: X...", lift just that clause back out
                int idx = f.description.indexOf("Algorithm: ");
                if (idx >= 0) {
                    int end = f.description.indexOf(',', idx);
                    if (end < 0) end = f.description.indexOf('.', idx);
                    if (end > idx) return f.description.substring(idx, end);
                }
            }
        }
        return findings.size() == 1 ? findings.get(0).issueName : findings.size() + " findings";
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    private static String rawHeader(UrlAnalysisResult result, String name) {
        for (Map.Entry<String, String> e : result.rawHeaders.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return null;
    }

    // ------ Set-Cookie parsing (mirrors CookieAnalyzer's own private parsing) ------------------

    private static List<ParsedCookie> parseSetCookie(String raw) {
        List<ParsedCookie> out = new ArrayList<>();
        if (raw == null || raw.isBlank()) return out;
        for (String line : raw.split("\n")) {
            line = line.trim();
            if (line.isBlank()) continue;
            out.add(new ParsedCookie(parseCookieName(line), line, parseCookieAttrs(line)));
        }
        return out;
    }

    private static String parseCookieName(String cookieStr) {
        int semi = cookieStr.indexOf(';');
        String nameVal = semi > 0 ? cookieStr.substring(0, semi) : cookieStr;
        int eq = nameVal.indexOf('=');
        return (eq > 0 ? nameVal.substring(0, eq) : nameVal).trim();
    }

    private static List<String> parseCookieAttrs(String cookieStr) {
        String[] parts = cookieStr.split(";");
        List<String> attrs = new ArrayList<>();
        for (int i = 1; i < parts.length; i++) attrs.add(parts[i].trim().toLowerCase(Locale.ROOT));
        return attrs;
    }

    private static String flagsSummaryFor(List<String> attrs) {
        boolean secure   = attrs.stream().anyMatch(a -> a.equals("secure"));
        boolean httpOnly = attrs.stream().anyMatch(a -> a.equals("httponly"));
        String sameSite  = attrs.stream().filter(a -> a.startsWith("samesite="))
                .map(a -> a.substring("samesite=".length())).findFirst().orElse(null);

        StringBuilder sb = new StringBuilder();
        sb.append(secure ? "Secure" : "-Secure");
        sb.append(' ').append(httpOnly ? "HttpOnly" : "-HttpOnly");
        sb.append(' ').append(sameSite != null ? "SameSite=" + capitalize(sameSite) : "-SameSite");
        return sb.toString();
    }

    private static String capitalize(String s) {
        return s.isEmpty() ? s : Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    // ------ Row data / filter predicates ---------------------------------------------------------------------------------------------------------------------------

    private Object[] cookieRowData(CookieGroup g) {
        return new Object[]{g.severity, "Cookie", g.cookieName, g.host, g.flagsSummary, g.affected.size()};
    }

    private Object[] authRowData(AuthGroup g) {
        return new Object[]{g.severity, g.kind, g.displayName, g.host, g.claimsSummary, g.affected.size()};
    }

    private boolean passesFilter(Severity severity, String host, String name) {
        String hostF = hostFilter.getText().trim().toLowerCase(Locale.ROOT);
        String search = searchFilter.getText().trim().toLowerCase(Locale.ROOT);
        String sev = (String) sevFilter.getSelectedItem();
        if (sev != null && !sev.startsWith("All") && !severity.label.equalsIgnoreCase(sev)) return false;
        if (!hostF.isEmpty() && !host.toLowerCase(Locale.ROOT).contains(hostF)) return false;
        if (!search.isEmpty() && !name.toLowerCase(Locale.ROOT).contains(search)) return false;
        return true;
    }

    // ------ Incremental table mutation helpers ---------------------------------------------------------------------------------------------------------

    private void upsertGroupRow(Object key, Object[] rowData, boolean passesFilter) {
        int idx = groupKeysByRow.indexOf(key);
        if (!passesFilter) {
            if (idx >= 0) { groupModel.removeRow(idx); groupKeysByRow.remove(idx); }
            return;
        }
        if (idx >= 0) {
            for (int c = 0; c < rowData.length; c++) groupModel.setValueAt(rowData[c], idx, c);
        } else {
            groupModel.addRow(rowData);
            groupKeysByRow.add(key);
        }
    }

    private Object[] affectedRowData(UrlAnalysisResult r) {
        String path = r.path + (r.probeLabel != null ? "  [" + r.probeLabel + "]" : "");
        return new Object[]{
                r.host, path, r.statusCode > 0 ? r.statusCode : "",
                r.contentLength >= 0 ? r.contentLength : "",
                r.timestamp.format(DateTimeFormatter.ofPattern("HH:mm:ss"))
        };
    }

    private void upsertAffectedRow(UrlAnalysisResult r, boolean passesFilter) {
        String rk = r.host + "|" + r.rowKey();
        int idx = affectedKeysByRow.indexOf(rk);
        if (!passesFilter) {
            if (idx >= 0) { reqModel.removeRow(idx); affectedKeysByRow.remove(idx); shownAffectedByKey.remove(rk); updateAffectedCount(); }
            return;
        }
        Object[] rowData = affectedRowData(r);
        if (idx >= 0) {
            for (int c = 0; c < rowData.length; c++) reqModel.setValueAt(rowData[c], idx, c);
        } else {
            reqModel.addRow(rowData);
            affectedKeysByRow.add(rk);
        }
        shownAffectedByKey.put(rk, r);
        updateAffectedCount();
    }


    private void updateAffectedCount() {
        if (selectedGroupKey == null) return;
        String label = selectedGroupLabel();
        if (label != null) affectedLabel.setText(label + " - " + affectedKeysByRow.size() + " request(s) affected");
    }

    /** Cookie name, or auth token's display name, for whichever group is currently selected. */
    private String selectedGroupLabel() {
        if (selectedGroupKey instanceof AuthKey ak) {
            AuthGroup g = authGroups.get(ak);
            return g != null ? g.kind + " - " + g.displayName : null;
        }
        CookieGroup g = cookieGroups.get(selectedGroupKey);
        return g != null ? g.cookieName : null;
    }

    // ------ Group table full (re)population, explicit user actions only ------------------------

    private void rebuildGroupModel() {
        groupModel = new DefaultTableModel(COOKIE_COLS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
            @Override public Class<?> getColumnClass(int c) { return c == 0 ? Severity.class : Object.class; }
        };
        groupTable.setModel(groupModel);
        groupTable.setShowGrid(true);
        groupTable.setGridColor(new Color(220, 220, 220));
        groupTable.setIntercellSpacing(new Dimension(1, 1));
        groupTable.getColumnModel().getColumn(0).setCellRenderer(new SeverityRenderer());
        groupTable.getColumnModel().getColumn(0).setMaxWidth(90);  // Severity
        groupTable.getColumnModel().getColumn(1).setMaxWidth(90);  // Kind
        groupTable.getColumnModel().getColumn(5).setMaxWidth(80);  // Requests
        if (groupTable.getRowSorter() != null) {
            groupTable.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.ASCENDING)));
        }
    }

    private void refreshGroupTable() {
        groupModel.setRowCount(0);
        groupKeysByRow.clear();

        List<Map.Entry<String, CookieGroup>> cookieEntries = new ArrayList<>(cookieGroups.entrySet());
        cookieEntries.sort(Comparator.comparingInt((Map.Entry<String, CookieGroup> e) -> e.getValue().severity.order)
                .thenComparing(e -> e.getValue().cookieName.toLowerCase(Locale.ROOT)));
        for (var e : cookieEntries) {
            CookieGroup g = e.getValue();
            if (!passesFilter(g.severity, g.host, g.cookieName)) continue;
            groupModel.addRow(cookieRowData(g));
            groupKeysByRow.add(e.getKey());
        }

        List<Map.Entry<AuthKey, AuthGroup>> authEntries = new ArrayList<>(authGroups.entrySet());
        authEntries.sort(Comparator.comparingInt((Map.Entry<AuthKey, AuthGroup> e) -> e.getValue().severity.order)
                .thenComparing(e -> e.getValue().displayName.toLowerCase(Locale.ROOT)));
        for (var e : authEntries) {
            AuthGroup g = e.getValue();
            if (!passesFilter(g.severity, g.host, authSearchText(g))) continue;
            groupModel.addRow(authRowData(g));
            groupKeysByRow.add(e.getKey());
        }
    }

    private void onGroupSelected() {
        int viewRow = groupTable.getSelectedRow();
        if (viewRow < 0) { selectedGroupKey = null; selectedAffectedKey = null; populateAffectedTable(List.of(), null); return; }
        int modelRow = groupTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= groupKeysByRow.size()) return;

        Object newKey = groupKeysByRow.get(modelRow);
        if (!Objects.equals(newKey, selectedGroupKey)) selectedAffectedKey = null;
        selectedGroupKey = newKey;
        populateAffectedTableForSelectedGroup();
    }

    private void populateAffectedTableForSelectedGroup() {
        Collection<UrlAnalysisResult> affected;
        if (selectedGroupKey instanceof AuthKey ak) {
            AuthGroup g = authGroups.get(ak);
            affected = g != null ? g.affected.values() : null;
        } else {
            CookieGroup g = cookieGroups.get(selectedGroupKey);
            affected = g != null ? g.affected.values() : null;
        }
        if (affected == null) { populateAffectedTable(List.of(), null); return; }

        List<UrlAnalysisResult> filtered = new ArrayList<>();
        for (UrlAnalysisResult r : affected) {
            if (!passesAffectedFilters(r)) continue;
            filtered.add(r);
        }
        String label = selectedGroupLabel() + " - " + filtered.size() + " request(s) affected";
        populateAffectedTable(filtered, label);
    }

    private void populateAffectedTable(List<UrlAnalysisResult> affected, String label) {
        reqModel.setRowCount(0);
        affectedKeysByRow.clear();
        shownAffectedByKey.clear();
        int restoreModelRow = -1;
        for (int i = 0; i < affected.size(); i++) {
            UrlAnalysisResult r = affected.get(i);
            String rk = r.host + "|" + r.rowKey();
            reqModel.addRow(affectedRowData(r));
            affectedKeysByRow.add(rk);
            shownAffectedByKey.put(rk, r);
            if (rk.equals(selectedAffectedKey)) restoreModelRow = i;
        }
        affectedLabel.setText(label != null ? label : "Select a row above to see the requests that carried it.");

        int targetModelRow = restoreModelRow >= 0 ? restoreModelRow : (affected.isEmpty() ? -1 : 0);
        if (targetModelRow >= 0) {
            int viewRow = reqTable.convertRowIndexToView(targetModelRow);
            if (viewRow >= 0) reqTable.getSelectionModel().setSelectionInterval(viewRow, viewRow);
        }
    }

    // ------ Public API ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public void clearAll() {
        rows.clear();
        cookieGroups.clear();
        authGroups.clear();
        selectedGroupKey = null;
        selectedAffectedKey = null;
        groupModel.setRowCount(0);
        groupKeysByRow.clear();
        populateAffectedTable(List.of(), null);
    }

    /** Remediation text as a hover tooltip, same pattern as LoggerPanel's issue rows. */
    private String groupRowTooltip(java.awt.event.MouseEvent e) {
        int viewRow = groupTable.rowAtPoint(e.getPoint());
        if (viewRow < 0) return null;
        int modelRow = groupTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= groupKeysByRow.size()) return null;
        Object k = groupKeysByRow.get(modelRow);

        // Plain text, not HTML: Burp's own tooltip renderer draws the string as-is instead of
        // interpreting markup, an <html>/<b>/<br> version showed the raw tag characters to the
        // user instead of formatting anything.
        if (k instanceof AuthKey ak) {
            AuthGroup g = authGroups.get(ak);
            if (g == null || g.representative == null) return null;
            return g.kind + "  -  " + g.displayName + "\n" +
                    g.representative.issueName + "  -  Severity: " + g.severity.label + "\n\n" +
                    g.representative.description;
        }
        CookieGroup g = cookieGroups.get(k);
        if (g == null) return null;
        if (g.representative == null) {
            return g.cookieName + "\n" +
                    "Secure, HttpOnly and SameSite are all configured correctly, no issues found.";
        }
        return g.cookieName + "\n" +
                g.representative.issueName + "  -  Severity: " + g.severity.label + "\n\n" +
                g.representative.description;
    }

    private static javax.swing.event.DocumentListener simpleListener(Runnable r) {
        return new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
        };
    }
}
