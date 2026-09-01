package com.b3xal.headeranalyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.analyzer.HeaderRules;
import com.b3xal.headeranalyzer.analyzer.RetestTracker;
import com.b3xal.headeranalyzer.model.*;
import com.b3xal.headeranalyzer.ui.render.ClipboardUtil;

import javax.swing.*;
import java.awt.*;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Report tab, evidence built for a screenshot: a clean, consistent dashboard of the 6
 * foundational security headers plus disclosed technology, designed to be pasted straight into a
 * professional pentest report.
 *
 * Scoped to whichever URL is selected in the Logger (mirrors DetailPanel).
 */
public final class ReportPanel extends JPanel {

    private final ConcurrentHashMap<String, DomainData> domainStore;
    private final RetestTracker retestTracker;
    private final MontoyaApi api;
    private final HeaderAnalysisEngine engine;

    private UrlAnalysisResult currentResult;

    private final JLabel contextLabel = new JLabel("Select a row in the Logger to generate a report");
    private final JPanel content = new JPanel();
    private final JScrollPane scroll;

    // Follows Burp's own theme instead of a fixed light palette: this panel used to hardcode
    // light-mode colors unconditionally, which looked broken/inverted under Burp's dark theme
    // (a bright white card list sitting inside an otherwise dark suite). Computed once at
    // construction, Burp's theme doesn't change mid-session. Card status colors below (Status enum)
    // deliberately mirror Tailwind's actual red/green/amber-50/200/600/900 palette, since this
    // report is designed to be pasted straight into reports that use that same visual language.
    private boolean dark;
    private Color pageBg, toolbarBg, toolbarBorder, mutedText, descText;
    private JPanel toolbar;

    /** The 6 foundational headers this report focuses on (canonical set, see plan decision). */
    private static final String[][] SEC_HEADERS = {
        {"Strict-Transport-Security", "HSTS",          "Enforces HTTPS and prevents downgrade to HTTP (MITM)."},
        {"X-Content-Type-Options",    "MIME sniffing", "Prevents browsers mis-interpreting response MIME types."},
        {"X-Frame-Options",           "Clickjacking",  "Stops the page being embedded in attacker-controlled iframes."},
        {"Referrer-Policy",           "Referrer leak", "Controls how much of the URL is sent in the Referer header."},
        {"X-XSS-Protection",          "XSS filter",    "Legacy browser XSS filter, deprecated and removed from all modern browsers."},
        // CSP can contain several independent weaknesses and therefore has the only expandable
        // foundational-header card. Keep it last so that expansion never pushes the other five
        // rows further down in a screenshot.
        {"Content-Security-Policy",   "CSP",           "Restricts which scripts/resources load, primary XSS defence."},
    };

    public ReportPanel(ConcurrentHashMap<String, DomainData> domainStore, RetestTracker retestTracker,
                        MontoyaApi api, HeaderAnalysisEngine engine) {
        super(new BorderLayout());
        this.domainStore  = domainStore;
        this.retestTracker = retestTracker;
        this.api          = api;
        this.engine       = engine;

        this.dark = api.userInterface().currentTheme() == burp.api.montoya.ui.Theme.DARK;
        updateThemePalette();

        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(pageBg);
        content.setBorder(BorderFactory.createEmptyBorder(18, 20, 28, 20));

        scroll = new JScrollPane(content, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        scroll.setBorder(null);

        toolbar = buildToolbar();
        add(toolbar, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        showEmpty();
    }

    /** Every card targets this width. Finding cards use {@link CardGridLayout}: up to 3 columns
     * (never more, however wide the window gets), every cell the SAME width and height (the max
     * across all cards in that grid), a uniform, deliberately spreadsheet-like grid rather than
     * a masonry/flow layout where row heights vary card to card. */
    private static final int CARD_WIDTH = 240;
    private static final int SHADOW = 3;
    /** Description/retest text's wrap width: card width minus its own left+right padding (16+16)
     * and the status icon column (24px icon + 10px BorderLayout gap). */
    private static final int CARD_TEXT_WIDTH = CARD_WIDTH - 32 - 34;

    private JPanel buildToolbar() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(toolbarBg);
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, toolbarBorder));
        contextLabel.setFont(contextLabel.getFont().deriveFont(Font.ITALIC, 11f));
        contextLabel.setForeground(mutedText);
        contextLabel.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 6));

        JButton retestBtn = new JButton("Retest This Page");
        retestBtn.setToolTipText("Replays the original request for this URL and re-verifies every finding shown below");
        retestBtn.addActionListener(e -> retestPage());

        JButton themeBtn = new JButton(dark ? "Light report" : "Dark report");
        themeBtn.setToolTipText("Toggle only the Report content theme; Burp's global theme is unchanged");
        themeBtn.addActionListener(e -> {
            dark = !dark;
            updateThemePalette();
            themeBtn.setText(dark ? "Light report" : "Dark report");
            applyLocalTheme();
        });

        JButton copyMdBtn = new JButton("Copy as Markdown");
        copyMdBtn.addActionListener(e -> {
            ClipboardUtil.copyText(buildMarkdown());
            JOptionPane.showMessageDialog(this, "Report copied to clipboard as Markdown.",
                    "Copied", JOptionPane.INFORMATION_MESSAGE);
        });

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 4));
        actions.setOpaque(false);
        actions.add(retestBtn);
        actions.add(themeBtn);
        actions.add(copyMdBtn);

        p.add(contextLabel, BorderLayout.CENTER);
        p.add(actions, BorderLayout.EAST);
        return p;
    }

    private void updateThemePalette() {
        pageBg        = dark ? new Color(17, 24, 39)    : new Color(243, 245, 249);
        toolbarBg     = dark ? new Color(31, 41, 55)    : new Color(248, 249, 252);
        toolbarBorder = dark ? new Color(55, 65, 81)    : new Color(215, 220, 228);
        mutedText     = dark ? new Color(156, 163, 175) : new Color(110, 120, 135);
        descText      = dark ? new Color(182, 188, 196) : new Color(90, 100, 115);
    }

    private void applyLocalTheme() {
        content.setBackground(pageBg);
        scroll.getViewport().setBackground(pageBg);
        if (toolbar != null) {
            toolbar.setBackground(toolbarBg);
            toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, toolbarBorder));
        }
        contextLabel.setForeground(mutedText);
        if (currentResult != null) rebuild(); else showEmpty();
    }

    // ------ Public API ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public void show(UrlAnalysisResult result) {
        currentResult = result;
        SwingUtilities.invokeLater(() -> {
            contextLabel.setText("Report for  " + result.host + result.path +
                    (result.probeLabel != null ? "  [" + result.probeLabel + "]" : "") +
                    "  ·  " + result.findings.size() + " findings  ·  " + result.getTimestampStr());
            rebuild();
        });
    }

    /** Convenience overload used when only host/path are known (looks up the latest result). */
    public void showUrl(String host, String path) {
        DomainData dd = domainStore.get(host);
        if (dd == null) { showEmpty(); return; }
        dd.getUrlResults().values().stream()
                .filter(r -> r.path.equals(path))
                .findFirst()
                .ifPresentOrElse(this::show, this::showEmpty);
    }

    public void clearAll() {
        currentResult = null;
        showEmpty();
        contextLabel.setText("Select a row in the Logger to generate a report");
    }

    // ------ Report builder ------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private void rebuild() {
        content.removeAll();
        content.add(reportHeader());
        content.add(vgap(20));

        content.add(sectionHeader("SECURITY HEADERS", "The 6 foundational HTTP security headers", new Color(41, 128, 185)));
        content.add(vgap(8));
        content.add(buildSecuritySection());
        content.add(vgap(24));

        content.add(sectionHeader("TECHNOLOGY & INFORMATION DISCLOSURE",
                "Headers/fingerprints that expose server technology and internal infrastructure, " +
                "aggregated across every request analyzed on this host",
                new Color(192, 57, 43)));
        content.add(vgap(8));
        content.add(buildDisclosureSection());

        List<HeaderFinding> cookieFindings = currentResult.findings.stream()
                .filter(f -> f.category == HeaderFinding.Category.COOKIE).toList();
        if (!cookieFindings.isEmpty()) {
            content.add(vgap(24));
            content.add(sectionHeader("COOKIES", "Set-Cookie attribute findings", new Color(142, 68, 173)));
            content.add(vgap(8));
            content.add(buildCookieSection(cookieFindings));
        }

        content.revalidate();
        content.repaint();
    }

    private void showEmpty() {
        content.removeAll();
        JLabel l = new JLabel("Select a row in the Logger tab.");
        l.setForeground(Color.GRAY);
        l.setFont(l.getFont().deriveFont(Font.ITALIC, 13f));
        l.setAlignmentX(LEFT_ALIGNMENT);
        content.add(l);
        content.revalidate();
        content.repaint();
    }

    private JPanel reportHeader() {
        JPanel p = new JPanel(new BorderLayout(4, 4)) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(44, 62, 80));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                g2.dispose();
            }
        };
        p.setOpaque(false);
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));
        p.setBorder(BorderFactory.createEmptyBorder(12, 18, 12, 18));

        JLabel title = new JLabel(currentResult.host + currentResult.path);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        title.setForeground(Color.WHITE);

        String ts = java.time.LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
        JLabel sub = new JLabel("Quimera Security Report  ·  " + ts +
                (currentResult.statusCode > 0 ? "  ·  HTTP " + currentResult.statusCode : ""));
        sub.setFont(sub.getFont().deriveFont(Font.PLAIN, 11f));
        sub.setForeground(new Color(176, 190, 197));

        p.add(title, BorderLayout.CENTER);
        p.add(sub, BorderLayout.SOUTH);
        return p;
    }

    private JPanel sectionHeader(String title, String subtitle, Color accent) {
        JPanel p = new JPanel(new BorderLayout(4, 2));
        p.setOpaque(false);
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 48));
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 2, 0, accent),
                BorderFactory.createEmptyBorder(4, 2, 6, 2)));
        JLabel t = new JLabel(title);
        t.setFont(t.getFont().deriveFont(Font.BOLD, 12f));
        t.setForeground(accent);
        JLabel s = new JLabel(subtitle);
        s.setFont(s.getFont().deriveFont(Font.PLAIN, 10f));
        s.setForeground(mutedText);
        p.add(t, BorderLayout.NORTH);
        p.add(s, BorderLayout.CENTER);
        return p;
    }

    // ------ Section 1: 6 foundational headers ------------------------------------------------------------------------------------------------------------

    private JPanel buildSecuritySection() {
        JPanel matrix = new JPanel();
        matrix.setLayout(new BoxLayout(matrix, BoxLayout.Y_AXIS));
        matrix.setOpaque(true);
        matrix.setBackground(dark ? new Color(24, 32, 46) : Color.WHITE);
        matrix.setBorder(BorderFactory.createLineBorder(
                dark ? new Color(55, 65, 81) : new Color(215, 220, 228), 1));
        Map<String, String> headers = ci(currentResult.rawHeaders);

        for (int i = 0; i < SEC_HEADERS.length; i++) {
            String[] spec = SEC_HEADERS[i];
            String hdr = spec[0], label = spec[1], desc = spec[2];
            String value = headers.get(hdr);
            RowInfo ri = evaluateSecurityHeader(hdr, value);
            if (hdr.equals("Content-Security-Policy") && value != null) {
                List<HeaderFinding> weaknesses = cspFindings();
                if (!weaknesses.isEmpty()) {
                    ri = new RowInfo(Status.WARNING, trunc(value, 118),
                            weaknesses.size() + " CSP weakness" + (weaknesses.size() == 1 ? "" : "es") + " detected.");
                }
            }
            String retestNote = retestNoteFor(hdr);
            matrix.add(buildMatrixRow(hdr, label, desc, ri, retestNote, true));
            if (i < SEC_HEADERS.length - 1) matrix.add(vgap(2));
        }

        matrix.setAlignmentX(LEFT_ALIGNMENT);
        matrix.setMaximumSize(new Dimension(Integer.MAX_VALUE, matrix.getPreferredSize().height));
        return matrix;
    }

    /** Dense, screenshot-oriented full-width row. Keeping DESCRIPTION and FINDING beneath the
     * title instead of in adjacent columns makes them immune to Burp split-pane compression. */
    private JPanel buildMatrixRow(String headerName, String shortLabel, String description,
                                  RowInfo ri, String auxiliaryNote, boolean verifiedNote) {
        // In the six foundational-header matrix, every actionable failure is visually red.
        // WARNING/LEGACY remain amber elsewhere, where they represent a softer classification.
        Status visualStatus = verifiedNote && (ri.status == Status.WARNING || ri.status == Status.LEGACY)
                ? Status.MISSING : ri.status;
        JPanel row = new JPanel() {
            @Override protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(visualStatus.color(dark));
                g.fillRect(0, 0, 4, getHeight());
            }
        };
        row.setLayout(new BoxLayout(row, BoxLayout.Y_AXIS));
        row.setOpaque(true);
        row.setBackground(visualStatus.cardBg(dark));
        row.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0,
                        dark ? new Color(55, 65, 81) : new Color(225, 229, 235)),
                BorderFactory.createEmptyBorder(9, 12, 9, 10)));

        JPanel top = new JPanel(new BorderLayout(8, 0));
        top.setOpaque(false);
        top.setAlignmentX(LEFT_ALIGNMENT);
        top.setMaximumSize(new Dimension(Integer.MAX_VALUE, 21));

        JLabel name = new JLabel(headerName + (shortLabel.equals(headerName) ? "" : "   " + shortLabel));
        name.setFont(name.getFont().deriveFont(Font.BOLD, 12f));
        name.setForeground(dark ? new Color(243, 244, 246) : new Color(25, 30, 38));
        JLabel status = new JLabel("●  " + matrixStatus(ri.status));
        status.setFont(status.getFont().deriveFont(Font.BOLD, 11f));
        status.setForeground(visualStatus.color(dark));
        top.add(name, BorderLayout.CENTER);
        top.add(status, BorderLayout.EAST);
        row.add(top);

        row.add(compactReportLine("DESCRIPTION", description, descText, false));

        String observed = matrixObservedValue(ri);
        String findingText = observed;
        if (ri.note != null && !ri.note.isBlank())
            findingText += (findingText.isBlank() ? "" : ", ") + ri.note;
        row.add(compactReportLine("FINDING", findingText,
                dark ? new Color(205, 210, 218) : new Color(55, 64, 76), true));

        if (auxiliaryNote != null) {
            JLabel auxiliary = new JLabel((verifiedNote ? "✓ " : "") + trunc(auxiliaryNote, 48));
            auxiliary.setToolTipText(auxiliaryNote);
            auxiliary.setFont(auxiliary.getFont().deriveFont(verifiedNote ? Font.BOLD : Font.PLAIN, 9f));
            auxiliary.setForeground(verifiedNote
                    ? (dark ? new Color(120, 220, 160) : new Color(39, 120, 60))
                    : mutedText);
            auxiliary.setAlignmentX(LEFT_ALIGNMENT);
            row.add(auxiliary);
        }

        if (headerName.equals("Content-Security-Policy") && ri.value != null
                && !ri.value.equalsIgnoreCase("Not present")) {
            List<HeaderFinding> weaknesses = cspFindings();
            if (!weaknesses.isEmpty()) row.add(buildCspWeaknesses(weaknesses));
        }

        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, row.getPreferredSize().height));
        return row;
    }

    /** One compact list inside the single CSP card. The policy remains in FINDING above; this
     * section contains only the distinct conclusions of the deep analyzer, ordered by severity. */
    private JPanel buildCspWeaknesses(List<HeaderFinding> findings) {
        JPanel list = new JPanel();
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        list.setOpaque(false);
        list.setAlignmentX(LEFT_ALIGNMENT);
        list.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0,
                        dark ? new Color(70, 78, 92) : new Color(220, 224, 230)),
                BorderFactory.createEmptyBorder(4, 0, 0, 0)));

        JLabel heading = new JLabel("WEAKNESSES   " + findings.size() + " detected");
        heading.setFont(heading.getFont().deriveFont(Font.BOLD, 9.5f));
        heading.setForeground(mutedText);
        heading.setAlignmentX(LEFT_ALIGNMENT);
        list.add(heading);

        for (HeaderFinding finding : findings) {
            JLabel item = new JLabel("●  " + finding.severity.label.toUpperCase(Locale.ROOT)
                    + "   " + trunc(finding.issueName, 100));
            item.setToolTipText(finding.issueName + ": " + finding.evidence);
            item.setFont(item.getFont().deriveFont(Font.PLAIN, 10.5f));
            item.setForeground(severityColor(finding.severity));
            item.setAlignmentX(LEFT_ALIGNMENT);
            item.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));
            list.add(item);
        }
        list.setMaximumSize(new Dimension(Integer.MAX_VALUE, list.getPreferredSize().height));
        return list;
    }

    private List<HeaderFinding> cspFindings() {
        Map<String, HeaderFinding> distinct = new LinkedHashMap<>();
        currentResult.findings.stream()
                .filter(f -> f.headerName.equalsIgnoreCase("Content-Security-Policy"))
                .filter(f -> f.category == HeaderFinding.Category.CSP
                        || f.category == HeaderFinding.Category.SECURITY_MISCONFIGURED)
                .sorted(Comparator.comparingInt(f -> f.severity.order))
                .forEach(f -> distinct.putIfAbsent(f.issueName, f));
        return new ArrayList<>(distinct.values());
    }

    private Color severityColor(Severity severity) {
        return switch (severity) {
            case HIGH -> dark ? new Color(248, 113, 113) : new Color(185, 28, 28);
            case MEDIUM -> dark ? new Color(251, 146, 60) : new Color(194, 65, 12);
            case LOW -> dark ? new Color(250, 204, 21) : new Color(161, 98, 7);
            case INFORMATION -> mutedText;
        };
    }

    private JPanel compactReportLine(String label, String text, Color color, boolean monospaceValue) {
        JPanel line = new JPanel(new BorderLayout(8, 0));
        line.setOpaque(false);
        line.setAlignmentX(LEFT_ALIGNMENT);
        if (label.equals("FINDING")) {
            line.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(1, 0, 0, 0,
                            dark ? new Color(70, 78, 92) : new Color(220, 224, 230)),
                    BorderFactory.createEmptyBorder(3, 0, 0, 0)));
            line.setMaximumSize(new Dimension(Integer.MAX_VALUE, 23));
        } else {
            line.setBorder(BorderFactory.createEmptyBorder(1, 0, 2, 0));
            line.setMaximumSize(new Dimension(Integer.MAX_VALUE, 19));
        }
        JLabel key = new JLabel(label);
        key.setFont(key.getFont().deriveFont(Font.BOLD, 9.5f));
        key.setForeground(label.equals("FINDING") ? color : mutedText);
        key.setPreferredSize(new Dimension(86, 15));
        JLabel value = new JLabel(trunc(text == null ? "" : text, 118));
        value.setToolTipText(text);
        value.setFont(monospaceValue
                ? new Font(Font.MONOSPACED, Font.PLAIN, 10)
                : value.getFont().deriveFont(Font.PLAIN, 10.5f));
        value.setForeground(color);
        line.add(key, BorderLayout.WEST);
        line.add(value, BorderLayout.CENTER);
        return line;
    }

    private static String matrixStatus(Status status) {
        return switch (status) {
            case SECURE -> "Secure configuration";
            case OK -> "Correctly absent";
            case WARNING -> "Weak configuration";
            case LEGACY -> "Legacy configuration";
            case MISSING -> "Header not present";
            case EXPOSED -> "Value exposed";
        };
    }

    private static String matrixObservedValue(RowInfo ri) {
        if (ri.value == null || ri.value.isBlank()) return "";
        return ri.value;
    }

    private String retestNoteFor(String headerName) {
        for (HeaderFinding f : currentResult.findings) {
            if (!f.headerName.equalsIgnoreCase(headerName)) continue;
            var rec = retestTracker.recordFor(currentResult.host, currentResult.path, f);
            if (rec.isPresent() && rec.get().status != FindingStatus.OPEN) return rec.get().statusSummary();
        }
        return null;
    }

    // ------ Section 2: disclosure / technology ---------------------------------------------------------------------------------------------------------

    // Derived from HeaderRules.java instead of duplicated by hand, avoids the two lists silently
    // diverging (e.g. after CDN-identity rules were removed from HeaderRules, they disappear from
    // this report automatically instead of needing a matching manual edit here).
    private static final List<String> DISC_HEADERS = HeaderRules.all().stream()
            .filter(r -> r.checks.stream().anyMatch(c -> c.category == HeaderFinding.Category.INFORMATION_DISCLOSURE))
            .map(r -> r.headerName)
            .filter(h -> !h.equalsIgnoreCase("Server-Timing"))
            .distinct()
            .toList();

    /** Unlike the 6 foundational headers above (deliberately scoped to the single selected
     * request, CSP/XFO/etc. are legitimately per-response), disclosure is a host-level property:
     * Server/X-Powered-By/X-Debug-Token-Link and friends are usually constant site-wide, but any
     * one of them can show up on only SOME endpoints (an error page, an API route, a debug
     * endpoint) and not the specific request the analyst happens to have selected in the Logger.
     * Scoping this section to currentResult alone silently dropped disclosure that was real but
     * only ever seen on a different URL of the same host, aggregating across every analyzed
     * request for this host instead reports what the host actually exposes. */
    private JPanel buildDisclosureSection() {
        DomainData dd = domainStore.get(currentResult.host);
        Collection<UrlAnalysisResult> hostResults = dd != null && !dd.getUrlResults().isEmpty()
                ? dd.getUrlResults().values() : List.of(currentResult);

        Map<String, String> exposedValue = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, HeaderFinding> exposedFinding = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, Integer> exposedCount = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (UrlAnalysisResult r : hostResults) {
            Set<String> countedOnResponse = new HashSet<>();
            for (HeaderFinding finding : r.findings) {
                if (finding.category != HeaderFinding.Category.INFORMATION_DISCLOSURE
                        || finding.headerName.equalsIgnoreCase("Server-Timing")
                        || !DISC_HEADERS.stream().anyMatch(h -> h.equalsIgnoreCase(finding.headerName))) continue;
                String value = finding.headerValue != null ? finding.headerValue
                        : ci(r.rawHeaders).get(finding.headerName);
                if (value == null) continue;
                exposedValue.putIfAbsent(finding.headerName, value);
                exposedFinding.putIfAbsent(finding.headerName, finding);
                if (countedOnResponse.add(finding.headerName.toLowerCase(Locale.ROOT)))
                    exposedCount.merge(finding.headerName, 1, Integer::sum);
            }
            // Existing rows may have been analyzed by an older engine version that filtered this
            // finding by response context. The Report is a host inventory, so recover the actual
            // observed header directly instead of incorrectly presenting it as clean/absent.
            String lastModified = ci(r.rawHeaders).get("Last-Modified");
            if (lastModified != null && !lastModified.isBlank()
                    && countedOnResponse.add("last-modified")) {
                exposedValue.putIfAbsent("Last-Modified", lastModified);
                exposedFinding.putIfAbsent("Last-Modified", new HeaderFinding(
                        "Content modification timestamp disclosure", "Last-Modified", lastModified,
                        "The response exposes when its content was last modified.",
                        "Observed Last-Modified: " + lastModified,
                        Severity.LOW, Confidence.CERTAIN,
                        HeaderFinding.Category.INFORMATION_DISCLOSURE));
                exposedCount.merge("Last-Modified", 1, Integer::sum);
            }
        }
        List<String> exposed = new ArrayList<>(exposedValue.keySet());
        List<String> clean = DISC_HEADERS.stream().filter(h -> !exposedValue.containsKey(h)).toList();

        List<TechFinding> techInventory = dd != null ? dd.getTechInventory() : currentResult.techFindings;

        JPanel sec = column();

        // When there is a disclosure, lead with the actionable security result and keep parsed
        // technology underneath it. With a clean disclosure result, technology becomes the useful
        // content and therefore moves above the compact all-clear row instead of making the report
        // open with an empty-looking status block.
        if (!exposed.isEmpty()) {
            sec.add(buildDisclosureMatrix(exposed, exposedValue, exposedFinding, exposedCount,
                    hostResults.size()));
            if (!techInventory.isEmpty()) {
                sec.add(vgap(10));
                sec.add(buildTechnologyGrid(techInventory));
            }
        } else {
            if (!techInventory.isEmpty()) {
                sec.add(buildTechnologyGrid(techInventory));
                sec.add(vgap(10));
            }
            sec.add(buildSuccessRow("No information disclosure headers found across "
                    + hostResults.size() + " analyzed request(s) on this host."));
        }

        if (!clean.isEmpty()) {
            sec.add(vgap(10));
            sec.add(buildCleanChips(clean));
        }
        return sec;
    }

    private JPanel buildDisclosureMatrix(List<String> exposed, Map<String, String> exposedValue,
                                          Map<String, HeaderFinding> exposedFinding,
                                          Map<String, Integer> exposedCount, int hostResultCount) {
        JPanel matrix = new JPanel();
        matrix.setLayout(new BoxLayout(matrix, BoxLayout.Y_AXIS));
        matrix.setOpaque(true);
        matrix.setBackground(dark ? new Color(24, 32, 46) : Color.WHITE);
        matrix.setBorder(BorderFactory.createLineBorder(
                dark ? new Color(55, 65, 81) : new Color(215, 220, 228), 1));
        for (int i = 0; i < exposed.size(); i++) {
            String hdr = exposed.get(i);
            String value = exposedValue.get(hdr);
            HeaderFinding finding = exposedFinding.get(hdr);
            int count = exposedCount.get(hdr);
            String seenNote = hostResultCount > 1
                    ? "Seen on " + count + " of " + hostResultCount + " analyzed requests"
                    : null;
            matrix.add(buildMatrixRow(hdr, finding.issueName, disclosureSummary(finding),
                    new RowInfo(Status.EXPOSED, value, finding.evidence), seenNote, false));
            if (i < exposed.size() - 1) matrix.add(vgap(2));
        }

        matrix.setAlignmentX(LEFT_ALIGNMENT);
        matrix.setMaximumSize(new Dimension(Integer.MAX_VALUE, matrix.getPreferredSize().height));
        return matrix;
    }

    private JPanel buildTechnologyGrid(List<TechFinding> techInventory) {
        JPanel techGrid = reportMatrix();
        for (int i = 0; i < techInventory.size(); i++) {
            TechFinding tf = techInventory.get(i);
            techGrid.add(buildMatrixRow(tf.sourceHeader, "Technology",
                    "Technology fingerprint parsed from " + tf.sourceHeader + ".",
                    new RowInfo(Status.EXPOSED, tf.display(),
                            "Remove or obscure " + tf.sourceHeader + " to reduce fingerprinting surface."),
                    null, false));
            if (i < techInventory.size() - 1) techGrid.add(vgap(2));
        }
        techGrid.setMaximumSize(new Dimension(Integer.MAX_VALUE, techGrid.getPreferredSize().height));
        return techGrid;
    }

    /** Report cards are screenshot summaries, not advisory pages. Keep the full explanation in
     * Detail/Advisory and use one compact, header-specific sentence here. */
    private static String disclosureSummary(HeaderFinding finding) {
        if (finding.headerName.equalsIgnoreCase("Last-Modified"))
            return "Exposes when the served content was last modified.";
        return "Response exposes information through " + finding.headerName + ".";
    }

    private JPanel buildCookieSection(List<HeaderFinding> cookieFindings) {
        JPanel sec = column();
        JPanel grid = reportMatrix();
        for (int i = 0; i < cookieFindings.size(); i++) {
            HeaderFinding f = cookieFindings.get(i);
            Status status = f.severity == Severity.INFORMATION ? Status.EXPOSED : Status.WARNING;
            String value = f.headerValue == null || f.headerValue.isBlank() ? "Detected" : f.headerValue;
            grid.add(buildMatrixRow(f.headerName, f.issueName, f.description,
                    new RowInfo(status, value, f.evidence), null, false));
            if (i < cookieFindings.size() - 1) grid.add(vgap(2));
        }
        grid.setMaximumSize(new Dimension(Integer.MAX_VALUE, grid.getPreferredSize().height));
        sec.add(grid);
        return sec;
    }

    /** Shared full-width container so every report inventory uses exactly the same visual
     * language and the same minimal separation between adjacent findings. */
    private JPanel reportMatrix() {
        JPanel matrix = new JPanel();
        matrix.setLayout(new BoxLayout(matrix, BoxLayout.Y_AXIS));
        matrix.setOpaque(true);
        matrix.setBackground(dark ? new Color(24, 32, 46) : Color.WHITE);
        matrix.setBorder(BorderFactory.createLineBorder(
                dark ? new Color(55, 65, 81) : new Color(215, 220, 228), 1));
        matrix.setAlignmentX(LEFT_ALIGNMENT);
        return matrix;
    }

    // ------ Card builder ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private JPanel buildCard(String headerName, String shortLabel, String description, RowInfo ri, String retestNote) {
        JPanel card = new JPanel(new BorderLayout(0, 8)) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int w = getWidth(), h = getHeight();
                // Subtle drop shadow (the component is a couple px taller/wider than the visible
                // card so the shadow has room to peek out bottom-right, see the shadowSlack-sized
                // extra border below), a flat rounded-rect used to look plain/2000s-CSS next to
                // the reference design's shadow-sm cards.
                g2.setColor(new Color(0, 0, 0, dark ? 90 : 22));
                g2.fillRoundRect(SHADOW, SHADOW, w - SHADOW, h - SHADOW, 12, 12);
                g2.setColor(ri.status.cardBg(dark));
                g2.fillRoundRect(0, 0, w - SHADOW, h - SHADOW, 12, 12);
                g2.setColor(ri.status.cardBorder(dark));
                g2.setStroke(new BasicStroke(1.2f));
                g2.drawRoundRect(0, 0, w - SHADOW - 1, h - SHADOW - 1, 12, 12);
                g2.dispose();
            }
        };
        card.setOpaque(false);
        card.setBorder(BorderFactory.createEmptyBorder(16, 16, 12 + SHADOW, 16 + SHADOW));

        JPanel top = new JPanel(new BorderLayout(10, 0));
        top.setOpaque(false);
        top.add(buildCircleIcon(ri.status), BorderLayout.WEST);

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setOpaque(false);

        JLabel nameLbl = new JLabel(headerName);
        nameLbl.setFont(nameLbl.getFont().deriveFont(Font.BOLD, 13f));
        nameLbl.setForeground(dark ? new Color(243, 244, 246) : new Color(20, 20, 25));
        nameLbl.setAlignmentX(LEFT_ALIGNMENT);
        textPanel.add(nameLbl);

        if (!shortLabel.equals(headerName)) {
            JLabel tagLbl = new JLabel(shortLabel);
            tagLbl.setFont(tagLbl.getFont().deriveFont(Font.PLAIN, 10f));
            tagLbl.setForeground(dark ? new Color(160, 168, 182) : new Color(120, 130, 145));
            tagLbl.setAlignmentX(LEFT_ALIGNMENT);
            textPanel.add(tagLbl);
        }

        JPanel descLbl = wrappingLabel(description, CARD_TEXT_WIDTH, descText, 11f, false);
        textPanel.add(Box.createVerticalStrut(4));
        textPanel.add(descLbl);

        if (retestNote != null) {
            Color retestColor = dark ? new Color(120, 220, 160) : new Color(39, 120, 60);
            JPanel retestLbl = wrappingLabel("✓ " + retestNote, CARD_TEXT_WIDTH, retestColor, 10f, true);
            textPanel.add(Box.createVerticalStrut(3));
            textPanel.add(retestLbl);
        }

        top.add(textPanel, BorderLayout.CENTER);

        JPanel footer = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 2));
        footer.setOpaque(false);
        footer.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, ri.status.cardBorder(dark)));
        JLabel footerLbl = new JLabel(buildFooterText(ri));
        footerLbl.setFont(new Font(Font.MONOSPACED, Font.BOLD, 11));
        footerLbl.setForeground(ri.status.color(dark));
        footer.add(footerLbl);

        card.add(top, BorderLayout.CENTER);
        card.add(footer, BorderLayout.SOUTH);

        // Reports this card's own natural (content-driven) preferred size to CardGridLayout,
        // which then takes the MAX width/height across every card in the grid and applies that
        // uniformly to all of them, giving the whole grid consistent cell sizes.
        card.setPreferredSize(new Dimension(CARD_WIDTH + SHADOW, card.getPreferredSize().height));
        return card;
    }

    private static String buildFooterText(RowInfo ri) {
        return switch (ri.status) {
            case SECURE  -> ri.value != null && !ri.value.isEmpty() ? ri.value : "Present and configured";
            case OK      -> ri.value != null && !ri.value.isEmpty() ? ri.value : "Absent (correct for this header)";
            case WARNING, LEGACY -> ri.value != null && !ri.value.isEmpty() ? ri.value : "Misconfigured";
            case MISSING -> "Header is missing";
            case EXPOSED -> ri.value != null && !ri.value.isEmpty() ? ri.value : "Value found";
        };
    }

    private JLabel buildCircleIcon(Status status) {
        return new JLabel() {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(status.color(dark));
                g2.setStroke(new BasicStroke(2f));
                g2.drawOval(2, 2, 17, 17);
                g2.setStroke(new BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                switch (status) {
                    case SECURE, OK -> g2.drawPolyline(new int[]{6, 9, 16}, new int[]{11, 15, 7}, 3);
                    case WARNING, LEGACY -> { g2.drawLine(10, 6, 10, 12); g2.fillOval(9, 15, 3, 3); }
                    default -> { g2.drawLine(7, 7, 14, 14); g2.drawLine(14, 7, 7, 14); }
                }
                g2.dispose();
            }
            @Override public Dimension getPreferredSize() { return new Dimension(24, 24); }
            @Override public Dimension getMinimumSize()   { return new Dimension(24, 24); }
            @Override public Dimension getMaximumSize()   { return new Dimension(24, 24); }
        };
    }

    private JPanel buildSuccessRow(String msg) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 9)) {
            @Override protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(Status.SECURE.color(dark));
                g.fillRect(0, 0, 4, getHeight());
            }
        };
        p.setBackground(Status.SECURE.cardBg(dark));
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        JLabel icon = new JLabel("✓");
        icon.setFont(icon.getFont().deriveFont(Font.BOLD, 14f));
        icon.setForeground(Status.SECURE.color(dark));
        JLabel lbl = new JLabel(msg);
        lbl.setFont(lbl.getFont().deriveFont(Font.BOLD, 12f));
        lbl.setForeground(Status.SECURE.color(dark));
        p.add(icon);
        p.add(lbl);
        return p;
    }

    private JPanel buildCleanChips(List<String> headers) {
        JPanel p = new JPanel(new WrapLayout(FlowLayout.LEFT, 5, 4));
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setOpaque(false);
        JLabel prefix = new JLabel("Not exposed: ");
        prefix.setFont(prefix.getFont().deriveFont(Font.PLAIN, 10f));
        prefix.setForeground(mutedText);
        p.add(prefix);
        for (String hdr : headers) {
            JLabel chip = new JLabel(hdr);
            chip.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
            chip.setForeground(Status.SECURE.color(dark));
            chip.setOpaque(true);
            chip.setBackground(Status.SECURE.cardBg(dark));
            chip.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(Status.SECURE.cardBorder(dark), 1),
                    BorderFactory.createEmptyBorder(2, 6, 2, 6)));
            p.add(chip);
        }
        return p;
    }

    // ------ Security header evaluator ---------------------------------------------------------------------------------------------------------------------------------------

    private RowInfo evaluateSecurityHeader(String hdr, String value) {
        boolean redirect = currentResult != null
                && currentResult.statusCode >= 300 && currentResult.statusCode < 400;
        boolean capabilityProbe = currentResult != null && currentResult.method != null
                && (currentResult.method.equalsIgnoreCase("OPTIONS")
                    || currentResult.method.equalsIgnoreCase("TRACE"));
        boolean representationPolicy = Set.of(
                "Content-Security-Policy", "X-Content-Type-Options",
                "X-Frame-Options", "Referrer-Policy").contains(hdr);
        if (value == null && representationPolicy && (redirect || capabilityProbe)) {
            return new RowInfo(Status.SECURE, "Not applicable",
                    redirect
                            ? "Redirect response: no document representation is rendered here."
                            : "Capability/probe response: document security headers are not evaluated.");
        }
        return switch (hdr) {
            case "Strict-Transport-Security" -> {
                if (value == null) yield new RowInfo(Status.MISSING, "Not present",
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
                String lc = value.toLowerCase();
                if (!lc.matches(".*max-age=\\d+.*")) yield new RowInfo(Status.WARNING, value, "max-age directive missing or invalid.");
                if (!lc.contains("includesubdomains")) yield new RowInfo(Status.WARNING, value, "Missing includeSubDomains.");
                yield new RowInfo(Status.SECURE, value, "Correctly configured.");
            }
            case "Content-Security-Policy" -> {
                if (value == null) yield new RowInfo(Status.MISSING, "Not present", "No CSP, scripts can load from any origin.");
                String lc = value.toLowerCase();
                boolean noNonce = !lc.contains("'nonce-") && !lc.contains("'sha256-") && !lc.contains("'sha384-") && !lc.contains("'sha512-");
                if ((lc.contains("'unsafe-inline'") && noNonce) || lc.contains("'unsafe-eval'"))
                    yield new RowInfo(Status.WARNING, trunc(value, 72), "'unsafe-inline'/'unsafe-eval' present.");
                if (lc.matches(".*script-src[^;]*\\*.*") || lc.matches(".*default-src[^;]*\\*.*"))
                    yield new RowInfo(Status.WARNING, trunc(value, 72), "Wildcard (*) defeats CSP.");
                yield new RowInfo(Status.SECURE, trunc(value, 72), "Policy configured.");
            }
            case "X-Content-Type-Options" -> {
                if (value == null) yield new RowInfo(Status.MISSING, "Not present", "Add: X-Content-Type-Options: nosniff");
                yield value.toLowerCase().contains("nosniff")
                        ? new RowInfo(Status.SECURE, value, "Correctly configured.")
                        : new RowInfo(Status.WARNING, value, "Value should be exactly 'nosniff'.");
            }
            case "X-Frame-Options" -> {
                if (value == null) yield new RowInfo(Status.MISSING, "Not present", "Add: X-Frame-Options: DENY");
                String uc = value.toUpperCase();
                if (uc.contains("ALLOW-FROM")) yield new RowInfo(Status.WARNING, value, "ALLOW-FROM is deprecated.");
                yield (uc.contains("DENY") || uc.contains("SAMEORIGIN"))
                        ? new RowInfo(Status.SECURE, value, "Correctly configured.")
                        : new RowInfo(Status.WARNING, value, "Unrecognised value.");
            }
            case "Referrer-Policy" -> {
                if (value == null) yield new RowInfo(Status.SECURE,
                        "Not present, protected by modern-browser default",
                        "Effective policy: strict-origin-when-cross-origin.");
                HeaderFinding finding = HeaderAnalysisEngine.analyzeReferrerPolicy(value);
                yield finding == null
                        ? new RowInfo(Status.SECURE, value, "Does not weaken the browser default.")
                        : new RowInfo(Status.WARNING, value, finding.description);
            }
            // Deprecated, removed from every evergreen browser (Chrome dropped its XSS Auditor in
            // 2019, Firefox never had one), OWASP/MDN both say absent or "0" are equally correct,
            // see HeaderRules' own X-XSS-Protection rule (non-mandatory, only fires on a non-zero
            // value). A red "missing" card here would contradict that and actively mislead: there
            // is nothing to add, the safe state IS its absence.
            case "X-XSS-Protection" -> {
                if (value == null) yield new RowInfo(Status.SECURE, "Not present",
                        "Correct, this deprecated header has no effect in any current browser, CSP is the real XSS defence.");
                String trimmed = value.trim();
                yield trimmed.equals("0")
                        ? new RowInfo(Status.SECURE, value, "Explicitly disabled, correct.")
                        : new RowInfo(Status.WARNING, value, "Active in a value other than '0': harmless in modern " +
                            "browsers but can itself introduce XSS in older ones. Remove the header or set it to '0'.");
            }
            default -> new RowInfo(Status.WARNING, value != null ? value : "Not present", "");
        };
    }

    // ------ Markdown export ---------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private String buildMarkdown() {
        if (currentResult == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("# Quimera Security Report, ").append(currentResult.host).append(currentResult.path).append("\n\n");
        sb.append("Generated: ").append(currentResult.getTimestampStr()).append("\n\n");
        sb.append("## Security Headers\n\n");
        sb.append("| Header | Status | Value |\n|---|---|---|\n");
        Map<String, String> headers = ci(currentResult.rawHeaders);
        for (String[] spec : SEC_HEADERS) {
            RowInfo ri = evaluateSecurityHeader(spec[0], headers.get(spec[0]));
            sb.append("| ").append(spec[0]).append(" | ").append(ri.status).append(" | ")
              .append(ri.value != null ? ri.value.replace("|", "\\|") : "").append(" |\n");
        }
        DomainData dd = domainStore.get(currentResult.host);
        List<TechFinding> techInventory = dd != null ? dd.getTechInventory() : currentResult.techFindings;
        if (!techInventory.isEmpty()) {
            sb.append("\n## Technology Fingerprint (aggregated across this host)\n\n");
            for (TechFinding tf : techInventory) sb.append("- ").append(tf).append("\n");
        }
        sb.append("\n## All Findings\n\n");
        for (HeaderFinding f : currentResult.findings) {
            sb.append("- **[").append(f.severity.label).append("]** ").append(f.issueName)
              .append(" (`").append(f.headerName).append("`)\n");
        }
        return sb.toString();
    }

    // ------ Retest ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private void retestPage() {
        if (currentResult == null) return;
        HttpRequest originalReq = currentResult.originalRequest;
        if (originalReq == null) {
            JOptionPane.showMessageDialog(this, "Original request wasn't captured for this row, can't retest.",
                    "Retest unavailable", JOptionPane.WARNING_MESSAGE);
            return;
        }
        new SwingWorker<UrlAnalysisResult, Void>() {
            @Override protected UrlAnalysisResult doInBackground() throws Exception {
                HttpRequestResponse rr = api.http().sendRequest(originalReq);
                if (rr.response() == null) return null;
                Map<String, String> headerMap = new LinkedHashMap<>();
                rr.response().headers().forEach(h ->
                        com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(headerMap, h.name(), h.value()));
                Map<String, String> requestHeaderMap = new LinkedHashMap<>();
                rr.request().headers().forEach(h ->
                        com.b3xal.headeranalyzer.util.HeaderMaps.addRequest(requestHeaderMap, h.name(), h.value()));
                UrlAnalysisResult fresh = engine.analyze(currentResult.url, headerMap, requestHeaderMap,
                        rr.response().statusCode(), rr.response().bodyToString(), rr.request().method(),
                        true, rr.request().bodyToString());
                try { fresh.rawRequest = rr.request().toString(); fresh.rawResponse = rr.response().toString(); } catch (Exception ignored) {}
                fresh.method = rr.request().method();
                fresh.statusCode = rr.response().statusCode();
                fresh.contentLength = rr.response().body().length();
                fresh.probeLabel = currentResult.probeLabel;
                fresh.originalRequest  = rr.request();
                fresh.originalResponse = rr.response();
                return fresh;
            }
            @Override protected void done() {
                try {
                    UrlAnalysisResult fresh = get();
                    if (fresh == null) return;
                    retestTracker.reconcile(fresh);
                    DomainData dd = domainStore.computeIfAbsent(fresh.host, DomainData::new);
                    dd.addResult(fresh);
                    show(fresh);
                } catch (Exception ignored) {}
            }
        }.execute();
    }

    // ------ Helpers ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private static Map<String, String> ci(Map<String, String> raw) {
        TreeMap<String, String> m = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (raw != null) m.putAll(raw);
        return m;
    }

    private static String trunc(String s, int max) { return s == null || s.length() <= max ? s : s.substring(0, max) + "…"; }
    /** Fixed-width wrapping label, not an HTML JLabel: Burp's look-and-feel sets the Swing
     * "html.disable" UIManager flag process-wide (same lesson already learned in LoggerPanel/
     * CookiePanel's tooltips), so the old "&lt;html&gt;&lt;div style='width:190px;...'&gt;"
     * JLabel rendered the raw markup as literal text instead of wrapping/coloring anything, and
     * since this whole panel is designed to remain screenshot-friendly, that garbled text was
     * going out in client-facing evidence.
     * NOT a JTextArea either, a first attempt built one and forced its wrap width via the usual
     * setSize()-then-getPreferredSize() trick, but under Burp's customized look-and-feel that
     * trick came back with a near-zero width before the component was actually realized/painted
     * (JTextArea's UI delegate needs a real, attached Graphics context to lay out wrapped text
     * correctly, Burp's L&F apparently doesn't supply one early enough), the visible symptom was
     * every line wrapping after 1-2 characters, text collapsed into a single narrow column
     * hugging the left edge. Wrapping the text into plain single-line JLabels ourselves via
     * FontMetrics.stringWidth() sidesteps that entirely, a single-line JLabel's preferred size
     * has never been ambiguous in any Swing L&F, there's no wrapping computation to get wrong. */
    private static JPanel wrappingLabel(String text, int width, Color color, float size, boolean italic) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setOpaque(false);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);

        Font font = new JLabel().getFont().deriveFont(italic ? Font.ITALIC : Font.PLAIN, size);
        FontMetrics fm = p.getFontMetrics(font);

        for (String line : wrapToWidth(text, fm, width)) {
            JLabel l = new JLabel(line);
            l.setFont(font);
            l.setForeground(color);
            l.setAlignmentX(Component.LEFT_ALIGNMENT);
            p.add(l);
        }
        return p;
    }

    /** Greedy word-wrap at a fixed pixel width, splitting on existing newlines first so a
     * description's own paragraph breaks are preserved. */
    private static List<String> wrapToWidth(String text, FontMetrics fm, int width) {
        List<String> lines = new ArrayList<>();
        for (String paragraph : text.split("\n", -1)) {
            StringBuilder line = new StringBuilder();
            for (String word : paragraph.split(" ")) {
                String candidate = line.length() == 0 ? word : line + " " + word;
                if (fm.stringWidth(candidate) > width && line.length() > 0) {
                    lines.add(line.toString());
                    line = new StringBuilder(word);
                } else {
                    line = new StringBuilder(candidate);
                }
            }
            lines.add(line.toString());
        }
        return lines;
    }
    private static JPanel column() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setOpaque(false);
        return p;
    }
    private static Component vgap(int h) { return Box.createRigidArea(new Dimension(0, h)); }

    private record RowInfo(Status status, String value, String note) {}

    /** Colors follow Tailwind's actual palette (red/green/amber-50/200/600, and their dark-mode
     * 900-at-low-opacity/800/400 equivalents), since this report is designed to be pasted straight
     * into write-ups that already use that visual language. */
    enum Status {
        SECURE, OK, WARNING, LEGACY, MISSING, EXPOSED;
        Color color(boolean dark) {
            return switch (this) {
                case SECURE, OK -> dark ? new Color(74, 222, 128)  : new Color(22, 163, 74);
                case WARNING, LEGACY -> dark ? new Color(251, 191, 36) : new Color(217, 119, 6);
                case MISSING, EXPOSED -> dark ? new Color(248, 113, 113) : new Color(220, 38, 38);
            };
        }
        Color cardBg(boolean dark) {
            return switch (this) {
                case SECURE, OK -> dark ? new Color(20, 45, 32) : new Color(240, 253, 244);
                case WARNING, LEGACY -> dark ? new Color(55, 42, 15) : new Color(255, 251, 235);
                case MISSING, EXPOSED -> dark ? new Color(50, 28, 28) : new Color(254, 242, 242);
            };
        }
        Color cardBorder(boolean dark) {
            return switch (this) {
                case SECURE, OK -> dark ? new Color(35, 80, 55) : new Color(187, 247, 208);
                case WARNING, LEGACY -> dark ? new Color(90, 70, 25) : new Color(253, 230, 138);
                case MISSING, EXPOSED -> dark ? new Color(90, 45, 45) : new Color(254, 202, 202);
            };
        }
    }

    /** Uniform card grid: up to maxCols columns (never more, however wide the container gets,
     * unlike GridLayout which is always exactly N), every cell the SAME width AND height, taken
     * as the max preferred size across every child currently in the grid, a deliberately
     * spreadsheet-like uniform look (see {@link WrapLayout} for the alternative, variable-row-
     * height masonry style used for the "Not exposed:" chips row, not what the finding cards
     * want). Column count adapts to available width, 1 on a narrow window up to maxCols on a wide
     * one, computed fresh on every layout pass. */
    private static class CardGridLayout implements LayoutManager {
        private final int maxCols, hgap, vgap;

        CardGridLayout(int maxCols, int hgap, int vgap) {
            this.maxCols = maxCols;
            this.hgap = hgap;
            this.vgap = vgap;
        }

        @Override public void addLayoutComponent(String name, Component comp) {}
        @Override public void removeLayoutComponent(Component comp) {}

        @Override public Dimension preferredLayoutSize(Container parent) { return compute(parent); }
        @Override public Dimension minimumLayoutSize(Container parent)   { return compute(parent); }

        private Dimension compute(Container parent) {
            synchronized (parent.getTreeLock()) {
                int n = parent.getComponentCount();
                Insets insets = parent.getInsets();
                if (n == 0) return new Dimension(insets.left + insets.right, insets.top + insets.bottom);
                Dimension cell = maxCellSize(parent);
                int cols = columnsFor(parent, cell.width, insets);
                int rows = (n + cols - 1) / cols;
                int w = cols * cell.width + (cols - 1) * hgap + insets.left + insets.right;
                int h = rows * cell.height + (rows - 1) * vgap + insets.top + insets.bottom;
                return new Dimension(w, h);
            }
        }

        @Override public void layoutContainer(Container parent) {
            synchronized (parent.getTreeLock()) {
                int n = parent.getComponentCount();
                if (n == 0) return;
                Insets insets = parent.getInsets();
                Dimension cell = maxCellSize(parent);
                int cols = columnsFor(parent, cell.width, insets);
                int i = 0;
                for (Component c : parent.getComponents()) {
                    int row = i / cols, col = i % cols;
                    int x = insets.left + col * (cell.width + hgap);
                    int y = insets.top  + row * (cell.height + vgap);
                    c.setBounds(x, y, cell.width, cell.height);
                    i++;
                }
            }
        }

        private Dimension maxCellSize(Container parent) {
            int w = 0, h = 0;
            for (Component c : parent.getComponents()) {
                Dimension d = c.getPreferredSize();
                w = Math.max(w, d.width);
                h = Math.max(h, d.height);
            }
            return new Dimension(w, h);
        }

        /** How many columns fit in the parent's CURRENT width, capped at maxCols, floored at 1.
         * Falls back to maxCols when the parent hasn't been given a real width yet (not yet
         * realized), matching WrapLayout's same not-yet-sized fallback above. */
        private int columnsFor(Container parent, int cellWidth, Insets insets) {
            int width = parent.getWidth();
            if (width <= 0 || cellWidth <= 0) return maxCols;
            int avail = width - insets.left - insets.right;
            int fit = (avail + hgap) / (cellWidth + hgap);
            return Math.max(1, Math.min(maxCols, fit));
        }
    }
}
