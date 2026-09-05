package com.b3xal.headeranalyzer.ui;

import burp.api.montoya.MontoyaApi;
import com.b3xal.headeranalyzer.analyzer.BulkAnalyzer;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.TechFinding;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.ui.render.SeverityRenderer;

import static com.b3xal.headeranalyzer.ui.render.ScrollUtil.scrollPane;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.*;
import java.util.function.Consumer;

/**
 * The main workspace. Grouped by header/issue (or technology) so a big scan doesn't dump
 * thousands of individual requests on you at once: pick an issue, see which requests it affects,
 * pick a request, see its detail (Request/Response etc. via the Detail panel).
 *
 * Live traffic updates the two tables INCREMENTALLY (add/update/remove exactly the row that
 * changed via DefaultTableModel.setValueAt/addRow/removeRow) rather than ever clearing and
 * rebuilding them wholesale, a full rebuild on every incoming request was what caused the
 * selection to visibly flicker/deselect under real traffic. Only explicit, infrequent user
 * actions (changing a filter, switching Issue/Technology mode, clicking a different group,
 * Clear) do a full repopulate, since that's genuinely new content, not a reload of what's
 * already there.
 */
public final class LoggerPanel extends JPanel {

    private enum Mode { ISSUE, TECH }

    // ------ Group model ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private static class IssueGroup {
        final String issueName, headerName;
        Severity severity = Severity.INFORMATION;
        Confidence confidence = Confidence.TENTATIVE;
        HeaderFinding representative; // worst-severity finding seen, backs the hover tooltip
        final LinkedHashMap<String, UrlAnalysisResult> affected = new LinkedHashMap<>();

        IssueGroup(String issueName, String headerName) {
            this.issueName = issueName;
            this.headerName = headerName;
        }

        void absorb(HeaderFinding f) {
            if (f.severity.order < severity.order) severity = f.severity;
            if (f.confidence.order < confidence.order) confidence = f.confidence;
            if (representative == null || f.severity.order < representative.severity.order) representative = f;
        }

        // category used to be tracked as its own field, but absorb() kept overwriting it with
        // whichever finding arrived last, giving an inconsistent value if anything ever filtered
        // on it. representative is already the worst-severity finding seen, its category is the
        // one that matters and there is nothing extra to keep in sync.
        HeaderFinding.Category category() { return representative != null ? representative.category : null; }

        Set<String> hosts() {
            Set<String> h = new LinkedHashSet<>();
            for (UrlAnalysisResult r : affected.values()) h.add(r.host);
            return h;
        }
    }

    private static class TechGroup {
        final String product, version;
        final LinkedHashMap<String, UrlAnalysisResult> affected = new LinkedHashMap<>();
        String sourceHeader = "";

        TechGroup(String product, String version) { this.product = product; this.version = version; }

        Set<String> hosts() {
            Set<String> h = new LinkedHashSet<>();
            for (UrlAnalysisResult r : affected.values()) h.add(r.host);
            return h;
        }
    }

    private final MontoyaApi api;
    private final BulkAnalyzer bulkAnalyzer;
    private final QuimeraSettings settings;

    // Every captured result, keyed by host+rowKey, the source of truth the groups are built from.
    private final Map<String, UrlAnalysisResult> rows = new LinkedHashMap<>();
    private final Map<String, IssueGroup> issueGroups = new LinkedHashMap<>();
    private final Map<String, TechGroup>  techGroups  = new LinkedHashMap<>();

    private Mode mode = Mode.ISSUE;
    private Object selectedGroupKey; // key into issueGroups or techGroups, whichever matches `mode`
    private String selectedAffectedKey; // host|rowKey of the selected row in the affected-requests table

    // ------ Group table (top), groupKeysByRow[i] is the group key backing groupModel row i ------------------------
    // Kept deliberately minimal: Confidence/Category/Hosts still drive the grouping logic, they're
    // just not separate always-visible columns anymore.
    private static final String[] ISSUE_COLS = {"Severity", "Issue", "Header", "Requests"};
    private static final String[] TECH_COLS  = {"Product", "Version", "Requests"};
    private DefaultTableModel groupModel;
    private final JTable groupTable = new JTable();
    private final List<Object> groupKeysByRow = new ArrayList<>();

    // ------ Affected requests table (bottom) ---------------------------------------------------------------------------------------------------------------
    private static final String[] REQ_COLS = {"Host", "Path", "Status", "Length", "Time"};
    private final DefaultTableModel reqModel = new DefaultTableModel(REQ_COLS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable reqTable = new JTable(reqModel);
    private final List<String> affectedKeysByRow = new ArrayList<>();
    private final Map<String, UrlAnalysisResult> shownAffectedByKey = new HashMap<>();
    private final JLabel affectedLabel = new JLabel("Select an issue above to see the requests affected by it.");

    // Positive/negative filters on the affected-requests table, independent of the group-table
    // filters above (Host/Severity/Search there scope WHICH issues show up top-left, these scope
    // WHICH of that issue's affected requests show up bottom-right). Each field has its own plain
    // "Exclude" checkbox (unchecked = include, the common case) rather than a typed "!" prefix,
    // comma-separated values inside one field all share that field's direction, e.g. Length "1234"
    // + Exclude checked hides every response that's exactly 1234 bytes.
    private final JTextField pathFilterReq   = new JTextField(9);
    private final JTextField statusFilterReq = new JTextField(6);
    private final JTextField lengthFilterReq = new JTextField(7);
    private final JCheckBox pathExcludeToggle   = new JCheckBox("Exclude");
    private final JCheckBox statusExcludeToggle = new JCheckBox("Exclude");
    private final JCheckBox lengthExcludeToggle = new JCheckBox("Exclude");

    private final JComboBox<String> modeCombo = new JComboBox<>(new String[]{"By Header / Issue", "By Technology"});
    private final JTextField hostFilter = new JTextField(10);
    private final JTextField searchFilter = new JTextField(12);
    private final JComboBox<String> sevFilter =
            new JComboBox<>(new String[]{"All Severities", "High", "Medium", "Low", "Information"});

    /** (result, headerToHighlight, issueNameHint): headerToHighlight is the header name of
     * whichever issue is currently open, so the Detail panel can auto-highlight it in the native
     * response editor. issueNameHint is that same issue's exact title (there can be more than one
     * issue per header, e.g. Server's version vs. family split), so the Detail panel's AI button
     * can look up and focus on that one specific finding instead of summarizing every finding on
     * the URL. Both null when no issue context applies (e.g. Technology mode). */
    @FunctionalInterface
    public interface RowSelectionListener {
        void onSelect(UrlAnalysisResult result, String headerHint, String issueNameHint);
    }

    private RowSelectionListener onRowSelected = (r, h, i) -> {};
    private Consumer<UrlAnalysisResult> onResultProduced = r -> {};
    private Runnable onClearAll = () -> {};

    public LoggerPanel(MontoyaApi api, BulkAnalyzer bulkAnalyzer, QuimeraSettings settings) {
        super(new BorderLayout());
        this.api          = api;
        this.bulkAnalyzer = bulkAnalyzer;
        this.settings     = settings;
        build();
    }

    public void setOnRowSelected(RowSelectionListener cb) { this.onRowSelected = cb; }
    public void setOnResultProduced(Consumer<UrlAnalysisResult> cb) { this.onResultProduced = cb; }
    public void setOnClearAll(Runnable cb)                          { this.onClearAll = cb; }

    // ------ Build ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private void build() {
        // Must be set before the first rebuildGroupModel() call, which applies the default
        // Severity sort key right after setModel() and needs getRowSorter() to already exist.
        groupTable.setAutoCreateRowSorter(true);
        rebuildGroupModel();

        groupTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        groupTable.setRowHeight(22);
        groupTable.setToolTipText(""); // enable tooltip dispatch; text is computed per-cell below
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
                onRowSelected.onSelect(r, currentIssueHeaderHint(), currentIssueNameHint());
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
        right.add(scrollPane(reqTable), BorderLayout.CENTER);

        // Findings on the left, requests affected by whichever one is selected on the right,
        // side by side, this whole pane is the top half of the Logger tab (Detail/Raw
        // request-response lives in the bottom half, wired up in QuimeraTab).
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, scrollPane(groupTable), right);
        split.setResizeWeight(0.5);
        // The 0-1 proportional overload only takes effect once the pane has real bounds, so defer
        // it a tick, otherwise it's computed against a zero size and the 50/50 default is lost.
        SwingUtilities.invokeLater(() -> split.setDividerLocation(0.5));

        add(buildToolbar(), BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        modeCombo.addActionListener(e -> {
            mode = modeCombo.getSelectedIndex() == 0 ? Mode.ISSUE : Mode.TECH;
            sevFilter.setEnabled(mode == Mode.ISSUE);
            selectedGroupKey = null;
            selectedAffectedKey = null;
            rebuildGroupModel();
            refreshGroupTable();
            populateAffectedTable(List.of(), null);
        });
        hostFilter.getDocument().addDocumentListener(simpleListener(this::refreshFiltersNow));
        searchFilter.getDocument().addDocumentListener(simpleListener(this::refreshFiltersNow));
        sevFilter.addActionListener(e -> refreshFiltersNow());

        // Path/Status/Length only scope the affected-requests table for whichever group is
        // currently selected, no need to touch the group table/selection at all. Also keep the
        // "Filters ▾ (n)" button label in sync so it's obvious from the collapsed bar alone
        // whether any of these three are actually narrowing the table right now.
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

    /** Label + field + its own Exclude checkbox, packed tight (small internal gap) so the trio
     * visually reads as one unit. Plain FlowLayout with a single uniform gap made the checkbox
     * look like it belonged to the NEXT field instead of the one right before it, since the gap
     * on both sides was identical, this fixes that by making the gap BETWEEN trios (set by the
     * caller) bigger than the gap WITHIN one. */
    private static JPanel buildFilterGroup(String label, JTextField field, JCheckBox exclude) {
        JPanel g = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        g.add(new JLabel(label));
        g.add(field);
        g.add(exclude);
        return g;
    }

    private final JButton filtersToggleBtn = new JButton();

    /** Path/Status/Length used to sit inline, always visible, which is exactly what wouldn't fit
     * once the pane got narrow (see WrapLayout above). Tucked behind a single toggle button now,
     * shown as a popup on click, so the row costs one button's worth of space when not in use and
     * the button's own label ("Filters ▾ (2)") still tells you at a glance whether something is
     * actively narrowing the table without having to open it. */
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

    /** Re-populates just the affected-requests table for whichever group is currently selected, a
     * no-op if nothing's selected (table's already empty then). Path/Status/Length filter changes
     * don't affect which groups exist or their Requests counts the way the host filter does
     * (those counts are host-scoped, not path/status/length-scoped, deliberately, an issue is
     * still "5 requests affected" regardless of what this table happens to be narrowed to right
     * now), so this only needs to touch the affected table, never the group table. */
    private void refreshAffectedFilterNow() {
        if (selectedGroupKey != null) populateAffectedTableForSelectedGroup();
    }

    /** Shared include/exclude filter for the affected-requests table's Path/Status/Length fields.
     * Blank filterText always passes. Comma-separated values all share the field's Include/Exclude
     * toggle state (exclude=true drops any row matching one of them, exclude=false keeps only rows
     * matching at least one). substring=true for free-text fields (Path), false for exact-value
     * fields (Status/Length) where a substring match would be misleading (e.g. "40" substring-
     * matching both 400 and 404). */
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
     * result belongs in the affected-requests table right now. The single place both
     * populateAffectedTableForSelectedGroup and addOrUpdateRow's incremental upserts go through,
     * so live traffic and an explicit filter-field edit narrow the table exactly the same way. */
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

    /** Filter changes are an explicit, low-frequency user action: full rebuild is fine here,
     * restoring the current selection afterward if it still matches the new filter. */
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

        // Host/Severity/Search used to live behind a "Filter ▾" popup button, now inline right
        // after the mode selector so they're visible and usable without an extra click.
        JPanel left = new JPanel(new WrapLayout(FlowLayout.LEFT, 6, 4));
        left.add(modeCombo);
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
        });
        left.add(clearFiltersBtn);

        JButton analyzeBtn = new JButton("Analyze ▾");
        analyzeBtn.setToolTipText("Passively re-analyze crawled traffic, or actively send requests to the whole target");
        analyzeBtn.addActionListener(e -> new AnalyzeDialog(
                SwingUtilities.getWindowAncestor(this), api, bulkAnalyzer, settings, onResultProduced).setVisible(true));

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> confirmClear());

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 4));
        actions.add(analyzeBtn);
        actions.add(clearBtn);

        p.add(left,    BorderLayout.CENTER);
        p.add(actions, BorderLayout.EAST);
        return p;
    }

    private void confirmClear() {
        int choice = JOptionPane.showConfirmDialog(this,
                "Clear all captured URLs, findings and retest history?",
                "Quimera - Clear All", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice == JOptionPane.YES_OPTION) onClearAll.run();
    }

    // ------ Ingest (incremental, never clears either table) ------------------------------------------------------------------------

    /** Must be called on the EDT (see QuimeraTab#onResultAdded).
     *
     * Deliberately no "removed association" handling: a finding, once evidenced by a real
     * request/response, stays listed under its issue/technology group for the rest of the
     * session, even if a LATER capture of the exact same URL (a 304 conditional revalidation, a
     * redirect, an empty body) doesn't happen to repeat the same header. That later response
     * isn't proof the issue went away, it's just a response type that structurally can't carry
     * the same information (applyContextFilter strips most header checks off 304/redirect/empty
     * responses on purpose, see HeaderAnalysisEngine), and treating its reduced finding set as
     * new ground truth used to silently pull affected URLs in and out of a group's Requests
     * count as ordinary browsing reloaded the same asset (e.g. a cached .css/.js/image
     * revalidating with 304 on every repeat visit). Retest (RetestTracker, DetailPanel/
     * ReportPanel's "Retest Selected") is the one sanctioned way to mark a finding fixed,
     * replaying the exact original request, not ordinary passive traffic. Same "only upgrades,
     * never downgrades" principle CookiePanel's ingestSessionLifecycleFindings already applies. */
    public void addOrUpdateRow(UrlAnalysisResult result) {
        String key = result.host + "|" + result.rowKey();
        rows.put(key, result);

        // ------ Issue groups ---------------------------------------------------------------------------------------------------------------------------------------------------------------
        // Cookie, auth-token and browser-storage findings get their own dedicated
        // Cookies & Auth tab/panel now, so they are deliberately excluded here to keep this Logger
        // scoped to headers, not mixed content.
        for (HeaderFinding f : result.findings) {
            if (isCookiesAndAuthCategory(f.category)) continue;
            String gk = f.issueName + "|" + f.headerName;
            IssueGroup g = issueGroups.computeIfAbsent(gk, k -> new IssueGroup(f.issueName, f.headerName));
            g.absorb(f);
            g.affected.put(key, result);
            if (mode == Mode.ISSUE) upsertGroupRow(gk, issueRowData(g), passesIssueFilter(g));
            if (mode == Mode.ISSUE && Objects.equals(selectedGroupKey, gk)) {
                upsertAffectedRow(result, passesAffectedFilters(result));
            }
        }

        // ------ Technology groups ------------------------------------------------------------------------------------------------------------------------------------------------
        for (TechFinding tf : result.techFindings) {
            TechGroup g = techGroups.computeIfAbsent(tf.key(), k -> new TechGroup(tf.product, tf.version));
            g.sourceHeader = tf.sourceHeader;
            g.affected.put(key, result);
            if (mode == Mode.TECH) upsertGroupRow(tf.key(), techRowData(g), passesTechFilter(g));
            if (mode == Mode.TECH && Objects.equals(selectedGroupKey, tf.key())) {
                upsertAffectedRow(result, passesAffectedFilters(result));
            }
        }
    }

    // ------ Row data / filter predicates ---------------------------------------------------------------------------------------------------------------------------

    private Object[] issueRowData(IssueGroup g) {
        return new Object[]{g.severity, g.issueName, g.headerName, countForHostFilter(g.affected)};
    }

    private Object[] techRowData(TechGroup g) {
        return new Object[]{g.product, g.version != null ? g.version : "-", countForHostFilter(g.affected)};
    }

    /** Requests count for the group's Requests column, restricted to the active host filter (if any)
     * so it matches what the affected-requests table actually shows once a host is filtered in. */
    private int countForHostFilter(Map<String, UrlAnalysisResult> affected) {
        String host = hostFilter.getText().trim().toLowerCase(Locale.ROOT);
        if (host.isEmpty()) return affected.size();
        int count = 0;
        for (UrlAnalysisResult r : affected.values()) {
            if (r.host.toLowerCase(Locale.ROOT).contains(host)) count++;
        }
        return count;
    }

    private boolean passesIssueFilter(IssueGroup g) {
        String host = hostFilter.getText().trim().toLowerCase(Locale.ROOT);
        String search = searchFilter.getText().trim().toLowerCase(Locale.ROOT);
        String sev = (String) sevFilter.getSelectedItem();
        if (sev != null && !sev.startsWith("All") && !g.severity.label.equalsIgnoreCase(sev)) return false;
        if (!host.isEmpty() && g.hosts().stream().noneMatch(h -> h.toLowerCase(Locale.ROOT).contains(host))) return false;
        if (!search.isEmpty()) {
            String hay = (g.issueName + " " + g.headerName).toLowerCase(Locale.ROOT);
            if (!hay.contains(search)) return false;
        }
        return true;
    }

    private boolean passesTechFilter(TechGroup g) {
        String host = hostFilter.getText().trim().toLowerCase(Locale.ROOT);
        String search = searchFilter.getText().trim().toLowerCase(Locale.ROOT);
        if (!host.isEmpty() && g.hosts().stream().noneMatch(h -> h.toLowerCase(Locale.ROOT).contains(host))) return false;
        if (!search.isEmpty()) {
            String hay = (g.product + " " + (g.version != null ? g.version : "")).toLowerCase(Locale.ROOT);
            if (!hay.contains(search)) return false;
        }
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
        String name = null;
        if (mode == Mode.ISSUE) {
            IssueGroup g = issueGroups.get(selectedGroupKey);
            if (g != null) name = g.issueName;
        } else {
            TechGroup g = techGroups.get(selectedGroupKey);
            if (g != null) name = g.product + (g.version != null ? " " + g.version : "");
        }
        if (name != null) affectedLabel.setText(name + " - " + affectedKeysByRow.size() + " request(s) affected");
    }

    // ------ Group table full (re)population, explicit user actions only ------------------------

    private void rebuildGroupModel() {
        String[] cols = mode == Mode.ISSUE ? ISSUE_COLS : TECH_COLS;
        groupModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
            @Override public Class<?> getColumnClass(int c) { return mode == Mode.ISSUE && c == 0 ? Severity.class : Object.class; }
        };
        groupTable.setModel(groupModel);
        groupTable.setShowGrid(true);
        groupTable.setGridColor(new Color(220, 220, 220));
        groupTable.setIntercellSpacing(new Dimension(1, 1));
        if (mode == Mode.ISSUE) {
            groupTable.getColumnModel().getColumn(0).setCellRenderer(new SeverityRenderer());
            groupTable.getColumnModel().getColumn(0).setMaxWidth(90);  // Severity
            groupTable.getColumnModel().getColumn(3).setMaxWidth(80);  // Requests
            // Default sort by Severity, and keep it that way as rows are incrementally added/
            // removed by live traffic, not just at the moment the table happens to be rebuilt.
            // Severity's natural ordering (HIGH, MEDIUM, LOW, INFORMATION) already matches worst-first.
            if (groupTable.getRowSorter() != null) {
                groupTable.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.ASCENDING)));
            }
        } else {
            groupTable.getColumnModel().getColumn(2).setMaxWidth(80);  // Requests
        }
    }

    private void refreshGroupTable() {
        groupModel.setRowCount(0);
        groupKeysByRow.clear();

        if (mode == Mode.ISSUE) {
            List<Map.Entry<String, IssueGroup>> entries = new ArrayList<>(issueGroups.entrySet());
            entries.sort(Comparator.comparingInt(e -> e.getValue().severity.order));
            for (var e : entries) {
                if (!passesIssueFilter(e.getValue())) continue;
                groupModel.addRow(issueRowData(e.getValue()));
                groupKeysByRow.add(e.getKey());
            }
        } else {
            List<Map.Entry<String, TechGroup>> entries = new ArrayList<>(techGroups.entrySet());
            entries.sort(Comparator.comparing(e -> e.getValue().product.toLowerCase(Locale.ROOT)));
            for (var e : entries) {
                if (!passesTechFilter(e.getValue())) continue;
                groupModel.addRow(techRowData(e.getValue()));
                groupKeysByRow.add(e.getKey());
            }
        }
    }

    private void onGroupSelected() {
        int viewRow = groupTable.getSelectedRow();
        if (viewRow < 0) { selectedGroupKey = null; selectedAffectedKey = null; populateAffectedTable(List.of(), null); return; }
        int modelRow = groupTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= groupKeysByRow.size()) return;

        Object newKey = groupKeysByRow.get(modelRow);
        if (!Objects.equals(newKey, selectedGroupKey)) selectedAffectedKey = null; // switched to a different issue
        selectedGroupKey = newKey;
        populateAffectedTableForSelectedGroup();
    }

    /** Full (re)population of the affected-requests table for whichever group is selected, used
     * only when the user picks a genuinely different group (or on filter/mode changes), never
     * from live traffic ingestion (see addOrUpdateRow, which upserts individual rows instead). */
    private void populateAffectedTableForSelectedGroup() {
        IssueGroup ig = mode == Mode.ISSUE ? issueGroups.get(selectedGroupKey) : null;
        TechGroup  tg = mode == Mode.TECH  ? techGroups.get(selectedGroupKey)  : null;
        if (ig == null && tg == null) { populateAffectedTable(List.of(), null); return; }

        Collection<UrlAnalysisResult> affected = ig != null ? ig.affected.values() : tg.affected.values();
        List<UrlAnalysisResult> filtered = new ArrayList<>();
        for (UrlAnalysisResult r : affected) {
            if (!passesAffectedFilters(r)) continue;
            filtered.add(r);
        }
        String label = ig != null
                ? ig.issueName + " - " + filtered.size() + " request(s) affected"
                : tg.product + " " + (tg.version != null ? tg.version : "") +
                  " - " + filtered.size() + " request(s) affected";
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
        affectedLabel.setText(label != null ? label : "Select an issue above to see the requests affected by it.");

        // Auto-open the first affected request so picking an issue immediately shows evidence in
        // the Request/Response panes below, no second click needed. Falls back to that instead of
        // restoring a stale selection that no longer applies to this group.
        int targetModelRow = restoreModelRow >= 0 ? restoreModelRow : (affected.isEmpty() ? -1 : 0);
        if (targetModelRow >= 0) {
            int viewRow = reqTable.convertRowIndexToView(targetModelRow);
            if (viewRow >= 0) reqTable.getSelectionModel().setSelectionInterval(viewRow, viewRow);
        }
    }

    // ------ Public API ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    /** Jumps straight to a URL's detail (Detail/Report panels), used after a single-URL analysis. */
    public void selectRow(String host, String path) {
        SwingUtilities.invokeLater(() -> {
            for (UrlAnalysisResult r : rows.values()) {
                if (r.host.equals(host) && (path == null || r.path.equals(path))) {
                    onRowSelected.onSelect(r, currentIssueHeaderHint(), currentIssueNameHint());
                    return;
                }
            }
        });
    }

    private static boolean isCookiesAndAuthCategory(HeaderFinding.Category c) {
        return c == HeaderFinding.Category.COOKIE || c == HeaderFinding.Category.AUTH
                || c == HeaderFinding.Category.STORAGE;
    }

    /** The header name of whichever issue is currently open in the top-left table (Issue mode
     * only), so the Detail panel knows which header to auto-highlight in the response. */
    private String currentIssueHeaderHint() {
        if (mode != Mode.ISSUE || selectedGroupKey == null) return null;
        IssueGroup g = issueGroups.get(selectedGroupKey);
        return g != null ? g.headerName : null;
    }

    /** The exact issue title of whichever issue is currently open (Issue mode only), so the
     * Detail panel's AI button can focus on that one specific finding. */
    private String currentIssueNameHint() {
        if (mode != Mode.ISSUE || selectedGroupKey == null) return null;
        IssueGroup g = issueGroups.get(selectedGroupKey);
        return g != null ? g.issueName : null;
    }

    public int rowCount() { return rows.size(); }

    public void clearAll() {
        rows.clear();
        issueGroups.clear();
        techGroups.clear();
        selectedGroupKey = null;
        selectedAffectedKey = null;
        groupModel.setRowCount(0);
        groupKeysByRow.clear();
        populateAffectedTable(List.of(), null);
    }

    public void shutdown() { /* bulkAnalyzer lifecycle owned by the extension */ }

    /** Remediation text lives here as a hover tooltip on the issue row instead of a separate
     * always-visible pane, since the top-left table already identifies the issue by name/header. */
    private String groupRowTooltip(java.awt.event.MouseEvent e) {
        int viewRow = groupTable.rowAtPoint(e.getPoint());
        if (viewRow < 0) return null;
        int modelRow = groupTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= groupKeysByRow.size()) return null;
        Object key = groupKeysByRow.get(modelRow);

        // Plain text, not HTML: Burp's own tooltip renderer draws the string as-is instead of
        // interpreting markup, an <html>/<b>/<code> version showed the raw tag characters to the
        // user instead of formatting anything.
        if (mode == Mode.ISSUE) {
            IssueGroup g = issueGroups.get(key);
            if (g == null || g.representative == null) return null;
            return g.issueName + "\n" +
                    "Header: " + g.headerName + "  -  Severity: " + g.severity.label + "\n\n" +
                    g.representative.description;
        } else {
            TechGroup g = techGroups.get(key);
            if (g == null) return null;
            return g.product + (g.version != null ? " " + g.version : "") + "\n" +
                    "Detected via " + g.sourceHeader;
        }
    }

    private static javax.swing.event.DocumentListener simpleListener(Runnable r) {
        return new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
        };
    }
}
