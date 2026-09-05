package com.b3xal.headeranalyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.b3xal.headeranalyzer.analyzer.ActiveHeaderScanner;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.analyzer.RetestTracker;
import com.b3xal.headeranalyzer.model.*;
import com.b3xal.headeranalyzer.util.JsonUtil;
import com.b3xal.headeranalyzer.util.JwtDisplay;
import com.b3xal.headeranalyzer.util.SafeLogging;

import static com.b3xal.headeranalyzer.ui.render.ScrollUtil.scrollPane;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Detail view for a single Logger row: Burp's native Request editor on the left, Response on the
 * right, same widgets as Repeater/Proxy. Findings already live in the Logger's top-left table, so
 * instead of a second findings list here, the response is auto-highlighted (Burp's native
 * search-match highlight) with the FULL VALUE of whichever header caused the currently selected
 * issue, not just the header name, so the whole thing lights up, not a fragment, or the worst
 * Medium+ finding if none is specifically selected. The Response side also carries an "Advisory"
 * tab (see {@link #advisoryPane}/{@link #updateAdvisory}), same idea as Burp's own Issue view's
 * Advisory, the finding's full explanation instead of only a hover tooltip on the Logger row. AI
 * analysis is a separate button that opens its result in a dialog.
 */
public final class DetailPanel extends JPanel {

    private final MontoyaApi api;
    private final RetestTracker retestTracker;
    private final HeaderAnalysisEngine engine;
    private final ActiveHeaderScanner activeScanner;
    private final Consumer<UrlAnalysisResult> onResultProduced;

    private static final String CARD_EMPTY = "empty";
    private static final String CARD_URL   = "url";
    private final CardLayout cards = new CardLayout();
    private final JPanel cardPanel = new JPanel(cards);
    private final JLabel titleLabel = new JLabel("Select a row in the Logger to see details");
    private final JLabel techLabel  = new JLabel(" ");

    // ------ HTTP panes (Burp's own native request/response editors, same look as Repeater/Proxy) ------
    private final HttpRequestEditor  reqEditor;
    private final HttpResponseEditor respEditor;

    // ------ Advisory (same idea as Burp's own Issue view: background/why/remediation text, one tab
    // to the left of Response). Real HTML via JEditorPane, not a plain JTextArea: unlike a
    // <html>-wrapped JLabel (broken under Burp's L&F, see the html.disable lesson elsewhere in
    // this codebase), JEditorPane's HTMLEditorKit does NOT go through Swing's BasicHTML/
    // "html.disable" check at all, it renders real HTML regardless, verified by rendering both
    // side by side to a PNG under html.disable=true before relying on it here. ------
    private final JEditorPane advisoryPane = new JEditorPane();
    // Captured once in buildAdvisoryPanel() after api.userInterface().applyThemeToComponent(),
    // the ACTUAL theme colors/fonts Burp is running, baked into advisoryHtml()'s inline CSS.
    private Color advisoryBg;
    private Color advisoryFg;
    private Font  advisoryBodyFont;
    private Font  advisoryEditorFont;

    private final JButton retestBtn = new JButton("Retest");
    private final JLabel  retestSummary = new JLabel(" ");
    private final JButton aiBtn = new JButton("Analyze with AI");
    private final JComboBox<String> probeExchangeSelector = new JComboBox<>();
    private final JPanel probeExchangeControl = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
    private boolean updatingProbeSelector;

    private UrlAnalysisResult currentResult;
    private String currentFocusHeader;    // header of the currently-open issue, if any
    private String currentFocusIssueName; // exact issue title of the currently-open issue, if any
    private boolean currentFocusIsRequestHeader; // whether currentFocusHeader is request- or response-side
    private boolean currentCookiesAuthOnly;

    public DetailPanel(MontoyaApi api, RetestTracker retestTracker, HeaderAnalysisEngine engine,
                        ActiveHeaderScanner activeScanner, Consumer<UrlAnalysisResult> onResultProduced) {
        super(new BorderLayout());
        this.api              = api;
        this.retestTracker    = retestTracker;
        this.engine           = engine;
        this.activeScanner    = activeScanner;
        this.onResultProduced = onResultProduced;
        this.reqEditor        = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.respEditor       = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        build();
    }

    private void build() {
        cardPanel.add(new JPanel(), CARD_EMPTY);
        cardPanel.add(buildUrlCard(), CARD_URL);
        cards.show(cardPanel, CARD_EMPTY);

        add(buildHeaderBar(), BorderLayout.NORTH);
        add(cardPanel,        BorderLayout.CENTER);
    }

    private JPanel buildHeaderBar() {
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        techLabel.setFont(techLabel.getFont().deriveFont(Font.PLAIN, 11f));
        techLabel.setForeground(Color.GRAY);

        JPanel textCol = new JPanel();
        textCol.setLayout(new BoxLayout(textCol, BoxLayout.Y_AXIS));
        titleLabel.setAlignmentX(LEFT_ALIGNMENT);
        techLabel.setAlignmentX(LEFT_ALIGNMENT);
        textCol.add(titleLabel);
        textCol.add(techLabel);
        textCol.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));

        aiBtn.setToolTipText("AI-powered security assessment of this URL's findings (opens in a dialog)");
        aiBtn.addActionListener(e -> { if (currentResult != null) runAiAnalysis(currentResult); });

        retestBtn.setToolTipText("Replays the exact original request for this URL and re-checks every finding");
        retestBtn.addActionListener(e -> retestPage());
        retestSummary.setFont(retestSummary.getFont().deriveFont(Font.ITALIC, 11f));
        retestSummary.setForeground(Color.GRAY);

        JPanel actionsRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
        probeExchangeControl.add(new JLabel("Validated service:"));
        probeExchangeControl.add(probeExchangeSelector);
        probeExchangeControl.setVisible(false);
        probeExchangeSelector.addActionListener(e -> {
            if (updatingProbeSelector || currentResult == null) return;
            int index = probeExchangeSelector.getSelectedIndex();
            if (index < 0 || index >= currentResult.probeExchanges.size()) return;
            HttpRequestResponse exchange = currentResult.probeExchanges.get(index);
            reqEditor.setRequest(exchange.request());
            respEditor.setResponse(exchange.response());
        });
        actionsRow.add(probeExchangeControl);
        actionsRow.add(retestSummary);
        actionsRow.add(aiBtn);
        actionsRow.add(retestBtn);

        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(220, 220, 220)));
        p.add(textCol,    BorderLayout.WEST);
        p.add(actionsRow, BorderLayout.EAST);
        return p;
    }

    /** Back to the original Request | Response side-by-side split, divider centered (Response
     * shown immediately, no extra click). Advisory is the LEFTMOST tab on the Response side,
     * {@code respEditor.uiComponent()} is Burp's own opaque widget with its own internal Pretty/
     * Raw/Hex tabs baked in, the Montoya API gives no way to inject an extra tab literally inside
     * that widget's own tab strip (there is no per-sub-tab access, only the whole editor as one
     * component), so "Advisory" ends up as its own tab immediately to the left of that whole
     * widget rather than beside Pretty/Raw/Hex individually, the closest this API allows to the
     * real Issue view's layout. */
    private JPanel buildUrlCard() {
        JTabbedPane responseTabs = new JTabbedPane();
        responseTabs.addTab("Advisory", buildAdvisoryPanel());
        responseTabs.addTab("Response", respEditor.uiComponent());
        responseTabs.setSelectedIndex(1); // Response visible by default, Advisory a click away to its left

        JSplitPane reqResp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                reqEditor.uiComponent(), responseTabs);
        reqResp.setResizeWeight(0.5);
        // setDividerLocation(double) only takes effect once the split pane actually has a real
        // size, calling it right here (construction time, size still 0x0) silently no-ops and the
        // divider ends up wherever the components' preferred sizes happen to fall, visibly not
        // centered. A one-shot listener that fires on the FIRST real resize (then removes itself)
        // is the reliable way to force a centered starting position regardless of when this panel
        // actually gets laid out inside QuimeraTab's own nested split panes.
        reqResp.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override public void componentResized(java.awt.event.ComponentEvent e) {
                reqResp.setDividerLocation(0.5);
                reqResp.removeComponentListener(this);
            }
        });

        JPanel p = new JPanel(new BorderLayout());
        p.add(reqResp, BorderLayout.CENTER);
        return p;
    }

    /** Same purpose as Burp's own native "Advisory" tab on a Scanner Issue: title, severity/
     * confidence/category line, full explanation, evidence block, real HTML via
     * {@link #advisoryPane} (see that field's own javadoc for why HTML actually works here despite
     * Burp's L&F disabling it for JLabel-style components). Colors/fonts come from Burp itself
     * ({@link MontoyaApi#userInterface()}'s {@code applyThemeToComponent}/{@code currentDisplayFont}/
     * {@code currentEditorFont}) rather than a hand-picked light/dark palette, HTML content ignores
     * Swing's UIManager entirely, so the actual resulting colors/fonts are read back off the
     * component AFTER theming and baked into the HTML's inline CSS in {@link #advisoryHtml}. */
    private JPanel buildAdvisoryPanel() {
        advisoryPane.setContentType("text/html");
        advisoryPane.setEditable(false);
        // Editable=false is what makes JEditorPane fire hyperlink events at all instead of
        // treating clicks as text-caret placement, see advisoryHtml's "want to dig deeper?" link.
        advisoryPane.addHyperlinkListener(e -> {
            if (e.getEventType() != HyperlinkEvent.EventType.ACTIVATED || e.getURL() == null) return;
            try {
                Desktop.getDesktop().browse(e.getURL().toURI());
            } catch (Exception ex) {
                SafeLogging.error(api, "[Quimera] could not open reference link: " + ex.getMessage());
            }
        });

        JPanel p = new JPanel(new BorderLayout());
        p.add(scrollPane(advisoryPane,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER),
                BorderLayout.CENTER);

        api.userInterface().applyThemeToComponent(p);
        advisoryBg = advisoryPane.getBackground();
        advisoryFg = advisoryPane.getForeground();
        advisoryBodyFont   = api.userInterface().currentDisplayFont();
        advisoryEditorFont = api.userInterface().currentEditorFont();

        advisoryPane.setText(advisoryHtml(null));
        return p;
    }

    /** Renders one finding as the Advisory's HTML body: bold issue title, a severity/confidence/
     * category/header meta line (severity colored with the SAME {@link Severity#color} used
     * everywhere else in Quimera, e.g. the status-bar legend), the full description, and an
     * evidence block in a boxed section using Burp's own editor font, same shape as Burp's own
     * native issue advisory (title, then background prose, then evidence). Muted/meta text and the
     * evidence box background are computed by blending the real theme foreground/background
     * {@link #buildAdvisoryPanel} captured, rather than separate hardcoded colors, so they track
     * WHATEVER theme Burp is actually running, not just a light/dark guess. */
    private String advisoryHtml(HeaderFinding f) {
        String bg     = hex(advisoryBg);
        String bodyFg = hex(advisoryFg);
        String metaFg = hex(blend(advisoryFg, advisoryBg, 0.45));
        String evBg   = hex(blend(advisoryBg, advisoryFg, 0.08));
        String bodyFontCss = cssFont(advisoryBodyFont, 12);
        String evFontCss   = cssFont(advisoryEditorFont, 11);

        StringBuilder sb = new StringBuilder();
        sb.append("<html><body style='background:").append(bg).append(";color:").append(bodyFg)
          .append(';').append(bodyFontCss).append(";margin:0;padding:10px 12px;'>");

        if (f == null) {
            sb.append("<div style='color:").append(metaFg).append(";'>No findings on this response.</div>");
            sb.append("</body></html>");
            return sb.toString();
        }

        String sevHex = hex(f.severity.color);

        sb.append("<div style='font-size:14px;font-weight:bold;margin-bottom:5px;'>")
          .append(escapeHtml(f.issueName)).append("</div>");

        sb.append("<div style='margin-bottom:12px;'>")
          .append("<span style='color:").append(sevHex).append(";font-weight:bold;'>")
          .append(f.severity.label.toUpperCase()).append("</span>")
          .append("<span style='color:").append(metaFg).append(";'> &middot; ")
          .append(f.confidence.label).append(" confidence &middot; ").append(f.category);
        if (f.headerName != null && !f.headerName.isBlank()) {
            sb.append(" &middot; ").append(escapeHtml(f.headerName));
        }
        sb.append("</span></div>");

        sb.append("<div>").append(escapeHtml(f.description).replace("\n", "<br>")).append("</div>");

        // A raw JWT/token/JSON blob as one unbroken base64/escaped string is unreadable, doesn't
        // show WHERE it came from vs. what it actually contains, and for a JWT specifically hides
        // exactly the claims (email, exp, roles, ...) that make the finding meaningful at a
        // glance. Split "where" from "what", and decode/pretty-print "what" when possible, same
        // idea as opening the token in jwt.io instead of staring at base64, just inline.
        boolean googleProbe = f.issueName != null && f.issueName.startsWith("PROBE ")
                && f.issueName.contains("Google API key");
        String location = googleProbe ? googleProbeSource(f.evidence)
                : JwtDisplay.locationPrefix(f.evidence, f.headerValue);
        if (location != null && !location.isBlank()) {
            sb.append("<div style='margin-top:14px;font-weight:bold;'>Found at</div>");
            sb.append("<div style='margin-top:2px;color:").append(metaFg).append(";'>")
              .append(escapeHtml(location)).append("</div>");
        }

        String decoded = googleProbe
                ? googleProbeEvidenceHtml(f.evidence, metaFg, evBg, bodyFg, evFontCss)
                : decodedContentHtml(f.headerValue, metaFg, evBg, bodyFg, evFontCss);
        if (decoded != null) {
            sb.append(decoded);
        } else if (f.evidence != null && !f.evidence.isBlank()) {
            // Nothing decodable (headerValue null/not a JWT/not JSON): fall back to the plain raw
            // evidence block exactly as before, no regression for the common "just a header name/
            // value pair" case.
            sb.append("<div style='margin-top:14px;font-weight:bold;'>Evidence</div>");
            sb.append("<div style='margin-top:4px;padding:8px;background:").append(evBg)
              .append(";color:").append(bodyFg).append(';').append(evFontCss)
              .append(";white-space:pre-wrap;word-break:break-all;'>")
              .append(escapeHtml(f.evidence)).append("</div>");
        }

        // A small, deliberately rare "want to dig deeper?" pointer, only present when the finding
        // itself set one (see HeaderFinding#referenceUrl), for the handful of findings whose real
        // exploit chain (cache poisoning, a named bypass technique, ...) deserves more than this
        // pane's own paragraph. HyperlinkListener registered in buildAdvisoryPanel opens it.
        if (f.referenceUrl != null && !f.referenceUrl.isBlank()) {
            sb.append("<div style='margin-top:14px;color:").append(metaFg).append(";'>")
              .append("Want to dig deeper? <a href='").append(escapeHtml(f.referenceUrl))
              .append("'>Read this</a></div>");
        }

        sb.append("</body></html>");
        return sb.toString();
    }

    private static String googleProbeSource(String evidence) {
        if (evidence == null) return null;
        for (String line : evidence.split("\\R")) {
            if (line.startsWith("Location: ")) return line.substring("Location: ".length());
        }
        return null;
    }

    /** Purpose-built Google probe presentation. The generic token renderer treated the key found
     * inside the curl command as a location suffix, causing the entire validation transcript to
     * appear twice as one flattened "Found at" line. */
    private static String googleProbeEvidenceHtml(String evidence, String metaFg, String evBg,
                                                   String bodyFg, String evFontCss) {
        if (evidence == null || evidence.isBlank()) return null;
        String[] lines = evidence.split("\\R", -1);
        StringBuilder html = new StringBuilder();
        String section = "";
        StringBuilder content = new StringBuilder();
        for (String line : lines) {
            boolean heading = line.equals("VALIDATION RESULT") || line.equals("SOURCE")
                    || line.equals("PROBE SUMMARY") || line.equals("RESPONSE")
                    || line.equals("IMPACT") || line.startsWith("REPRODUCTION: ");
            if (heading) {
                appendGoogleProbeSection(html, section, content.toString(), metaFg, evBg, bodyFg, evFontCss);
                section = line;
                content.setLength(0);
            } else {
                if (content.length() > 0) content.append('\n');
                content.append(line);
            }
        }
        appendGoogleProbeSection(html, section, content.toString(), metaFg, evBg, bodyFg, evFontCss);
        return html.toString();
    }

    private static void appendGoogleProbeSection(StringBuilder html, String heading, String content,
                                                  String metaFg, String evBg, String bodyFg,
                                                  String evFontCss) {
        if (heading.isBlank()) return;
        String title = heading.startsWith("REPRODUCTION: ") ? heading : heading.replace('_', ' ');
        html.append("<div style='margin-top:14px;font-weight:bold;'>")
                .append(escapeHtml(title)).append("</div>");
        if (heading.equals("PROBE SUMMARY")) {
            html.append("<div style='margin-top:4px;'>");
            for (String line : content.strip().split("\\R")) {
                if (line.isBlank()) continue;
                String color = line.startsWith("ACCEPTED") ? "#dc2626"
                        : line.startsWith("REJECTED") ? metaFg : "#d97706";
                html.append("<div style='padding:3px 6px;margin-bottom:2px;background:")
                        .append(evBg).append(";color:").append(color).append(';').append(evFontCss)
                        .append(";font-weight:").append(line.startsWith("ACCEPTED") ? "bold" : "normal")
                        .append(";'>").append(escapeHtml(line)).append("</div>");
            }
            html.append("</div>");
        } else {
            html.append("<div style='margin-top:4px;padding:8px;background:").append(evBg)
                    .append(";color:").append(bodyFg).append(';').append(evFontCss)
                    .append(";white-space:pre-wrap;word-break:break-word;'>")
                    .append(escapeHtml(content.strip())).append("</div>");
        }
    }

    /** headerValue decoded/pretty-printed into something actually readable: a JWT's header+
     * payload claims (so an exp timestamp or an email claim is legible instead of buried in
     * base64), or, failing that, headerValue itself pretty-printed if it's a raw JSON blob. Null
     * if headerValue is null/blank or neither shape applies, callers fall back to the plain
     * evidence box in that case. Decode logic lives in {@link JwtDisplay}, shared verbatim with
     * IssueFormatting so Burp's native Issues tab reads identically. */
    private String decodedContentHtml(String headerValue, String metaFg, String evBg, String bodyFg, String evFontCss) {
        if (headerValue == null || headerValue.isBlank()) return null;

        JwtDisplay.Decoded decoded = JwtDisplay.decode(headerValue);
        if (decoded != null) {
            if (decoded.headerJson() == null && decoded.payloadJson() == null) return null;
            StringBuilder sb = new StringBuilder();

            // Token: the raw compact string as-is, still shown even though it's also decoded
            // below, still what you paste into Repeater/jwt.io/a report.
            sb.append("<div style='margin-top:14px;font-weight:bold;'>Token</div>");
            sb.append(jsonBlockHtml(headerValue, evBg, bodyFg, evFontCss));

            // Decoded token: the header segment, pretty-printed JSON (alg/typ/kid, ...).
            if (decoded.headerJson() != null) {
                sb.append("<div style='margin-top:10px;font-weight:bold;'>Decoded token</div>");
                sb.append(jsonBlockHtml(decoded.headerJson(), evBg, bodyFg, evFontCss));
            }

            // Payload: the claims segment, pretty-printed JSON, this is where email/roles/sub/
            // etc actually become legible instead of buried in base64.
            if (decoded.payloadJson() != null) {
                sb.append("<div style='margin-top:10px;font-weight:bold;'>Payload</div>");
                sb.append(jsonBlockHtml(decoded.payloadJson(), evBg, bodyFg, evFontCss));
                // exp/iat/nbf/auth_time are Unix epoch seconds, meaningless to eyeball as raw
                // integers in the JSON block above, one line per field (raw value AND its
                // converted date), the "el time" a human actually wants, not buried in the JSON.
                if (!decoded.timestampLines().isEmpty()) {
                    sb.append("<div style='margin-top:10px;color:").append(metaFg).append(";font-size:11px;'>Timestamps</div>");
                    sb.append(jsonBlockHtml(String.join("\n", decoded.timestampLines()), evBg, bodyFg, evFontCss));
                }
            }
            return sb.toString();
        }

        String pretty = JwtDisplay.prettyJsonOrNull(headerValue);
        if (pretty != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("<div style='margin-top:14px;font-weight:bold;'>Decoded value</div>");
            sb.append(jsonBlockHtml(pretty, evBg, bodyFg, evFontCss));
            return sb.toString();
        }
        return null;
    }

    private static String jsonBlockHtml(String prettyJson, String evBg, String bodyFg, String evFontCss) {
        return "<div style='margin-top:2px;padding:8px;background:" + evBg + ";color:" + bodyFg + ";"
                + evFontCss + ";white-space:pre-wrap;word-break:break-word;'>"
                + escapeHtml(prettyJson) + "</div>";
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String hex(Color c) {
        if (c == null) return "#808080";
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    /** Blends toward {@code mix} by fraction {@code t} (0 = pure {@code base}, 1 = pure
     * {@code mix}), used to derive "muted text"/"subtle box background" colors straight from
     * Burp's own real foreground/background instead of separate hardcoded grays, so they track
     * whatever theme/skin Burp is actually running rather than an assumed light/dark pair. */
    private static Color blend(Color base, Color mix, double t) {
        if (base == null || mix == null) return base != null ? base : mix;
        return new Color(
            (int) Math.round(base.getRed()   * (1 - t) + mix.getRed()   * t),
            (int) Math.round(base.getGreen() * (1 - t) + mix.getGreen() * t),
            (int) Math.round(base.getBlue()  * (1 - t) + mix.getBlue()  * t));
    }

    /** CSS font-family/size from a real AWT Font (Burp's {@code currentDisplayFont()}/
     * {@code currentEditorFont()}), falls back to a generic family/defaultSize if font is null
     * (shouldn't happen against a real Burp instance, defensive only). */
    private static String cssFont(Font font, int defaultSizePx) {
        String family = font != null ? font.getFamily() : "sans-serif";
        int size = font != null ? font.getSize() : defaultSizePx;
        return "font-family:'" + family.replace("'", "") + "';font-size:" + size + "px";
    }

    // ------ Public API ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    /** highlightHeader: header NAME whose value should be highlighted in the response, the
     * currently open issue's header, from the Logger's top-left table. The actual VALUE for
     * this specific response is looked up from result.rawHeaders and searched for, so the whole
     * value lights up (not just the header name, and not just wherever it partially matches).
     * Null falls back to the worst Medium+ finding on this response, if any. */
    public void show(UrlAnalysisResult result, String highlightHeader) {
        show(result, highlightHeader, null);
    }

    /** Same as {@link #show(UrlAnalysisResult, String)}, plus the exact issue title of whichever
     * issue is currently open (there can be more than one issue per header), so the AI button can
     * focus its analysis on that one specific finding instead of summarizing the whole URL. */
    public void show(UrlAnalysisResult result, String highlightHeader, String highlightIssueName) {
        show(result, highlightHeader, highlightIssueName, false);
    }

    /** Same as {@link #show(UrlAnalysisResult, String, String)}, plus whether highlightHeader is a
     * REQUEST header (Authorization, Cookie, X-Api-Key, ...) rather than a response header. Cookie
     * findings are response-side (Set-Cookie) like every other header this panel has ever
     * highlighted, but Cookies & Auth's token findings are mostly request-side, and searching for
     * an Authorization value in the response editor would just never find it. */
    public void show(UrlAnalysisResult result, String highlightHeader, String highlightIssueName,
                      boolean isRequestHeader) {
        showScoped(result, highlightHeader, highlightIssueName, isRequestHeader, false);
    }

    /** Cookies & Auth detail must never fall back to an unrelated header finding from the same
     * HTTP exchange when a historical/grouped token representative is not present on this row. */
    public void showCookiesAuth(UrlAnalysisResult result, String highlightHeader,
                                String highlightIssueName, boolean isRequestHeader) {
        showScoped(result, highlightHeader, highlightIssueName, isRequestHeader, true);
    }

    private void showScoped(UrlAnalysisResult result, String highlightHeader, String highlightIssueName,
                            boolean isRequestHeader, boolean cookiesAuthOnly) {
        currentResult = result;
        currentFocusHeader = highlightHeader;
        currentFocusIssueName = highlightIssueName;
        currentFocusIsRequestHeader = isRequestHeader;
        currentCookiesAuthOnly = cookiesAuthOnly;
        titleLabel.setText(result.host + result.path +
                (result.probeLabel != null ? "  [" + result.probeLabel + "]" : "") +
                "  ·  " + result.findings.size() + " findings  ·  " + result.getTimestampStr());
        techLabel.setText(result.techFindings.isEmpty() ? " " :
                "Tech: " + result.techFindings.stream().map(TechFinding::display)
                        .reduce((a, b) -> a + ", " + b).orElse(""));
        retestSummary.setText(" ");
        boolean browserSnapshot = "browser".equals(result.probeLabel);
        retestBtn.setEnabled(!browserSnapshot && result.originalRequest != null);
        retestBtn.setToolTipText(browserSnapshot
                ? "Browser findings require a new live browser snapshot and cannot be reproduced by an HTTP replay"
                : "Replays the exact original request for this URL and re-checks every finding");
        if (browserSnapshot) {
            retestSummary.setText("Browser finding: revisit or refresh the page to capture a new live snapshot.");
        }
        updateAdvisory(result);
        updatingProbeSelector = true;
        probeExchangeSelector.removeAllItems();
        for (String label : result.probeExchangeLabels) probeExchangeSelector.addItem(label);
        probeExchangeControl.setVisible(!result.probeExchanges.isEmpty());
        if (!result.probeExchanges.isEmpty()) probeExchangeSelector.setSelectedIndex(0);
        updatingProbeSelector = false;
        if (result.originalRequest != null) reqEditor.setRequest(result.originalRequest);
        if (result.originalResponse != null) respEditor.setResponse(result.originalResponse);

        // Search state belongs to the previously selected row in Burp's native editor. Clear it
        // first so an unresolved virtual location can never leave stale text such as
        // "(response body)" visible after switching findings.
        reqEditor.setSearchExpression("");
        respEditor.setSearchExpression("");

        HeaderFinding searchFinding = findSearchFinding(result, highlightHeader, highlightIssueName);
        boolean googleProbe = result.probeLabel != null && result.probeLabel.contains("Google API key");
        if (googleProbe && searchFinding != null && searchFinding.headerValue != null
                && result.originalRequest != null) {
            // Validation keys live in the Google probe URL, not in Google's response body.
            positionRequestSearch(searchFinding.headerValue, result.originalRequest);
        }

        if (isRequestHeader) {
            String search = isVirtualLocation(highlightHeader)
                    ? searchFinding != null ? searchFinding.headerValue : null
                    : highlightHeader != null ? requestHeaderValueFor(result, highlightHeader) : null;
            if (search != null && result.originalRequest != null) {
                positionRequestSearch(search, result.originalRequest);
            }
        } else {
            String header = highlightHeader != null ? highlightHeader : worstMediumPlusHeader(result);
            String search = isVirtualLocation(header)
                    ? searchFinding != null ? searchFinding.headerValue : null
                    : header != null ? headerValueFor(result, header) : null;
            // Some aggregate findings use a synthetic location (for example "Cache status")
            // because several real headers contribute to one finding. Never leave that label in
            // Burp's search box: resolve one of the literal evidence fragments that is actually
            // present in this response instead.
            if (result.originalResponse != null
                    && (search == null || indexOfIgnoreCase(result.originalResponse.toString(), search) < 0)) {
                String evidenceSearch = evidenceFragmentInResponse(result.originalResponse.toString(),
                        searchFinding != null ? searchFinding.evidence : null);
                if (evidenceSearch != null) search = evidenceSearch;
            }
            if (browserSnapshot) {
                search = browserResponseSearch(result, searchFinding, search, highlightHeader);
            }
            if (!googleProbe && search != null) {
                // setSearchExpression alone gives the visible highlight; also drive the caret to
                // where that text actually is so the view jumps there too (setSearchExpression on
                // its own doesn't reliably scroll), same net effect as clicking an issue in Scanner.
                respEditor.setSearchExpression(search);
                if (result.originalResponse != null) {
                    int idx = indexOfIgnoreCase(result.originalResponse.toString(), search);
                    if (idx >= 0) respEditor.setCaretPosition(idx);
                }
            }
        }
        cards.show(cardPanel, CARD_URL);
    }

    private void positionRequestSearch(String search, HttpRequest request) {
        if (search == null || search.isBlank() || request == null) return;
        reqEditor.setSearchExpression(search);
        int idx = indexOfIgnoreCase(request.toString(), search);
        if (idx >= 0) reqEditor.setCaretPosition(idx);
    }

    /** Backward-compatible overload defaulting to no specific header hint. */
    public void show(UrlAnalysisResult result) { show(result, null); }

    private static String worstMediumPlusHeader(UrlAnalysisResult result) {
        HeaderFinding worst = null;
        for (HeaderFinding f : result.findings) {
            if (f.severity.order > Severity.MEDIUM.order) continue; // only Medium/High
            if (worst == null || f.severity.order < worst.severity.order) worst = f;
        }
        return worst != null ? worst.headerName : null;
    }

    /** The whole "Name: value" line as this specific response actually sent it, so the highlight
     * covers the entire header, not just the value. Falls back to the bare header name if this
     * response doesn't carry that header (e.g. a "missing" finding, nothing to highlight anyway). */
    private static String headerValueFor(UrlAnalysisResult result, String headerName) {
        for (Map.Entry<String, String> e : result.rawHeaders.entrySet()) {
            if (e.getKey().equalsIgnoreCase(headerName)) {
                return e.getValue() != null && !e.getValue().isBlank()
                        ? e.getKey() + ": " + e.getValue() : headerName;
            }
        }
        return headerName;
    }

    /** Request-side equivalent of {@link #headerValueFor}, for Authorization/Cookie/X-Api-Key-style
     * findings (see Cookies & Auth). Falls back to the bare header name if this request doesn't
     * carry it or wasn't captured. */
    private static String requestHeaderValueFor(UrlAnalysisResult result, String headerName) {
        if (result.originalRequest == null) return headerName;
        try {
            var h = result.originalRequest.header(headerName);
            return h != null && h.value() != null && !h.value().isBlank()
                    ? h.name() + ": " + h.value() : headerName;
        } catch (Exception ex) {
            return headerName;
        }
    }

    private static int indexOfIgnoreCase(String haystack, String needle) {
        if (haystack == null || needle == null || needle.isEmpty()) return -1;
        return haystack.toLowerCase().indexOf(needle.toLowerCase());
    }

    /** Returns a literal evidence item that exists in the response. Aggregate evidence joins
     * individual header lines with '|', while other analyzers commonly use newlines. */
    static String evidenceFragmentInResponse(String response, String evidence) {
        if (response == null || evidence == null || evidence.isBlank()) return null;
        String[] fragments = evidence.split("\\s*\\|\\s*|\\R");
        // An explicit HIT is more useful than Age because it directly explains why the aggregate
        // cache finding fired. Fall back to any other literal evidence (normally Age) afterwards.
        for (String fragment : fragments) {
            String candidate = fragment.trim();
            if (!candidate.isEmpty() && candidate.toLowerCase(Locale.ROOT).contains("hit")
                    && indexOfIgnoreCase(response, candidate) >= 0) return candidate;
        }
        for (String fragment : fragments) {
            String candidate = fragment.trim();
            if (!candidate.isEmpty() && indexOfIgnoreCase(response, candidate) >= 0) return candidate;
        }
        return null;
    }

    /** Resolve a browser finding to text that actually exists in BrowserEvidence's JSON body.
     * Raw scalar values (UUIDs, JWTs, opaque tokens, globals) are preferred. When the stored value
     * is itself serialized JSON, the snapshot necessarily escapes it, so use its JSON-string form.
     * Cookie attribute findings may not carry a value; their cookie name is still present in the
     * synthetic browserCookies array and is the best stable target. */
    private static String browserResponseSearch(UrlAnalysisResult result, HeaderFinding finding,
                                                String preferred, String headerName) {
        String response = result != null && result.originalResponse != null
                ? result.originalResponse.toString() : null;
        if (response == null) return preferred;
        if (preferred != null && indexOfIgnoreCase(response, preferred) >= 0) return preferred;
        if (finding != null && finding.headerValue != null && !finding.headerValue.isBlank()) {
            String jsonString = JsonUtil.write(finding.headerValue);
            if (indexOfIgnoreCase(response, jsonString) >= 0) return jsonString;
        }
        if (headerName != null && !headerName.isBlank()
                && indexOfIgnoreCase(response, headerName) >= 0) return headerName;
        return null;
    }

    private static boolean isBodyLocation(String name) {
        return name != null && (name.equalsIgnoreCase("(request body)")
                || name.equalsIgnoreCase("(response body)"));
    }

    /** Parenthesized source names are inventory metadata, not literal HTTP headers. Searching
     * for the label itself is never useful; search for the finding's observed value instead. */
    private static boolean isVirtualLocation(String name) {
        return name != null && name.startsWith("(") && name.endsWith(")");
    }

    public void clearAll() {
        currentResult = null;
        currentFocusHeader = null;
        currentFocusIssueName = null;
        currentFocusIsRequestHeader = false;
        retestSummary.setText(" ");
        titleLabel.setText("Select a row in the Logger to see details");
        techLabel.setText(" ");
        advisoryPane.setText(advisoryHtml(null));
        cards.show(cardPanel, CARD_EMPTY);
    }

    // ------ Advisory ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    /** Picks which finding the Advisory panel explains and renders it. Prefers the EXACT issue
     * currently open (same lookup {@link #runAiAnalysis} uses, {@link #findFocusedFinding}), that's
     * only available from the Headers Logger (each row there is one specific issue click). Cookies
     * & Auth's rows are grouped by header, not by individual issue, so it falls back to the worst
     * finding on that same header, and finally to the worst finding on the whole result if no
     * header hint is available either, always shows SOMETHING rather than an empty advisory. */
    private void updateAdvisory(UrlAnalysisResult result) {
        HeaderFinding f = findFocusedFinding(result);
        if (f != null && currentCookiesAuthOnly && !isCookiesAuthFinding(f)) f = null;
        if (f == null) f = worstFinding(result, currentFocusHeader, currentCookiesAuthOnly);
        // A Cookies & Auth group can retain historical affected rows after the token rotates.
        // If this particular exchange no longer contains the selected token/header, show no
        // advisory instead of substituting an unrelated cookie/auth issue (or formerly CSP).
        if (f == null && (!currentCookiesAuthOnly || currentFocusHeader == null))
            f = worstFinding(result, null, currentCookiesAuthOnly);
        advisoryPane.setText(advisoryHtml(f));
        advisoryPane.setCaretPosition(0);
    }

    /** Worst-severity finding, optionally narrowed to one header first (same "worst" tie-break
     * {@link #worstMediumPlusHeader} uses: lower Severity.order wins). headerName == null searches
     * every finding on the result. */
    private static HeaderFinding worstFinding(UrlAnalysisResult result, String headerName,
                                               boolean cookiesAuthOnly) {
        HeaderFinding worst = null;
        for (HeaderFinding f : result.findings) {
            if (cookiesAuthOnly && !isCookiesAuthFinding(f)) continue;
            if (headerName != null && !f.headerName.equalsIgnoreCase(headerName)) continue;
            if (worst == null || f.severity.order < worst.severity.order) worst = f;
        }
        return worst;
    }

    private static boolean isCookiesAuthFinding(HeaderFinding finding) {
        return finding.category == HeaderFinding.Category.COOKIE
                || finding.category == HeaderFinding.Category.AUTH
                || finding.category == HeaderFinding.Category.STORAGE;
    }

    // ------ Retest (whole page, replaying the exact original request) ---------------------------------------------

    private void retestPage() {
        if (currentResult == null) return;
        HttpRequest originalReq = currentResult.originalRequest;
        if (originalReq == null) {
            retestSummary.setText("Retest unavailable, original request was not captured for this row.");
            return;
        }

        retestSummary.setText("Retesting…");
        String url = currentResult.url;
        String host = currentResult.host;
        int before = currentResult.findings.size();
        // Snapshot whichever issue is open right now, retest runs in the background and the old
        // show(fresh) call at the end always fell back to worstMediumPlusHeader (usually the
        // Missing HSTS finding, MEDIUM and present on most targets) instead of restoring the
        // finding the analyst actually had open before clicking Retest.
        String focusHeader        = currentFocusHeader;
        String focusIssueName     = currentFocusIssueName;
        boolean focusIsRequestHdr = currentFocusIsRequestHeader;
        boolean focusCookiesAuthOnly = currentCookiesAuthOnly;
        String probeLabel         = currentResult.probeLabel;
        HeaderFinding previousFinding = findFocusedFinding(currentResult);
        if (previousFinding == null) {
            previousFinding = worstFinding(currentResult, focusHeader, focusCookiesAuthOnly);
        }
        final HeaderFinding advisoryBeforeRetest = previousFinding;
        final boolean supportedActiveProbe = ActiveHeaderScanner.supportsRetestLabel(probeLabel);

        new SwingWorker<UrlAnalysisResult, Void>() {
            @Override protected UrlAnalysisResult doInBackground() throws Exception {
                // Probe rows (CORS reflection / TRACE / HSTS downgrade) carry Category.ACTIVE
                // findings that only ActiveHeaderScanner's own status/body inspection produces,
                // engine.analyze() below has no knowledge of them at all. Re-running the same
                // probe is what actually re-verifies those findings, a plain passive re-analysis
                // would silently drop every one of them instead of confirming they're still open.
                UrlAnalysisResult probeResult = activeScanner.retest(probeLabel, url, originalReq);
                if (probeResult != null) return probeResult;
                if (supportedActiveProbe) return null;

                HttpRequestResponse rr = activeScanner.sendThrottled(originalReq);
                if (rr.response() == null) return null;

                Map<String, String> headerMap = new LinkedHashMap<>();
                rr.response().headers().forEach(h ->
                        com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(headerMap, h.name(), h.value()));

                Map<String, String> requestHeaderMap = new LinkedHashMap<>();
                rr.request().headers().forEach(h ->
                        com.b3xal.headeranalyzer.util.HeaderMaps.addRequest(requestHeaderMap, h.name(), h.value()));

                UrlAnalysisResult fresh = engine.analyze(url, headerMap, requestHeaderMap,
                        rr.response().statusCode(), rr.response().bodyToString(), rr.request().method(),
                        true, rr.request().bodyToString());
                try {
                    fresh.rawRequest  = rr.request().toString();
                    fresh.rawResponse = rr.response().toString();
                } catch (Exception ignored) {}
                fresh.method           = rr.request().method();
                fresh.statusCode       = rr.response().statusCode();
                fresh.contentLength    = rr.response().body().length();
                fresh.probeLabel       = currentResult.probeLabel;
                fresh.originalRequest  = rr.request();
                fresh.originalResponse = rr.response();
                return fresh;
            }

            @Override protected void done() {
                try {
                    UrlAnalysisResult fresh = get();
                    if (fresh == null) {
                        if (supportedActiveProbe) {
                            retestSummary.setText("Retest complete, the active finding was not reproduced.");
                            if (advisoryBeforeRetest != null) {
                                advisoryPane.setText(advisoryHtml(advisoryBeforeRetest));
                                advisoryPane.setCaretPosition(0);
                            }
                        } else {
                            retestSummary.setText("Retest failed, no response; the original advisory was kept.");
                        }
                        return;
                    }
                    retestTracker.reconcile(fresh);         // the only place retest status changes
                    onResultProduced.accept(fresh);         // updates domainStore/Logger/Report

                    int after = fresh.findings.size();
                    int fixed = Math.max(0, before - after);
                    String summary = fixed > 0
                            ? "Retest complete, " + fixed + " finding(s) resolved, " + after + " still open."
                            : "Retest complete, " + after + " finding(s) still open.";

                    if (currentResult != null && currentResult.host.equals(host)
                            && currentResult.rowKey().equals(fresh.rowKey())) {
                        showScoped(fresh, focusHeader, focusIssueName, focusIsRequestHdr,
                                focusCookiesAuthOnly);
                        if (advisoryBeforeRetest != null
                                && !containsFinding(fresh, advisoryBeforeRetest)) {
                            advisoryPane.setText(advisoryHtml(advisoryBeforeRetest));
                            advisoryPane.setCaretPosition(0);
                            summary += " Selected finding was not reproduced; original advisory retained.";
                        }
                    }
                    retestSummary.setText(summary);
                } catch (Exception ex) {
                    retestSummary.setText("Retest error: " + ex.getMessage());
                }
            }
        }.execute();
    }

    private static boolean containsFinding(UrlAnalysisResult result, HeaderFinding expected) {
        for (HeaderFinding finding : result.findings) {
            if (finding.issueName.equals(expected.issueName)
                    && finding.headerName.equalsIgnoreCase(expected.headerName)) return true;
        }
        return false;
    }

    // ------ AI (opens result in a dialog instead of a persistent tab) ------------------------------------------------

    private void runAiAnalysis(UrlAnalysisResult result) {
        if (!api.ai().isEnabled()) {
            JOptionPane.showMessageDialog(this,
                    "Burp AI is not enabled. Go to Settings > AI in Burp Suite Pro to use this feature.",
                    "AI Analysis", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // If a specific issue is open on the left (Logger's top-left table), focus the whole
        // prompt on that one finding, a client-ready writeup, instead of an aggregate summary of
        // every finding on the URL, that's what "explain this finding like a professional, why
        // it's reported, what the implications are" needs, one focused analysis, not a digest.
        HeaderFinding focused = findFocusedFinding(result);

        String dialogTitle = focused != null
                ? "AI Analysis, " + focused.issueName
                : "AI Analysis, " + result.host + result.path;
        String systemContent = focused != null ? focusedSystemPrompt() : summarySystemPrompt();
        String userContent   = focused != null ? focusedUserContent(result, focused) : summaryUserContent(result);

        JTextArea output = new JTextArea("Analyzing...");
        output.setEditable(false);
        output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        output.setLineWrap(true);
        output.setWrapStyleWord(true);
        output.setMargin(new Insets(8, 10, 8, 10));

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), dialogTitle,
                Dialog.ModalityType.MODELESS);
        dialog.setLayout(new BorderLayout());
        dialog.add(scrollPane(output), BorderLayout.CENTER);
        dialog.setSize(560, 420);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);

        aiBtn.setEnabled(false);

        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    var response = api.ai().prompt().execute(
                        Message.systemMessage(systemContent), Message.userMessage(userContent));
                    return response.content();
                } catch (Exception ex) { return "AI analysis failed: " + ex.getMessage(); }
            }
            @Override protected void done() {
                try { output.setText(get()); output.setCaretPosition(0); }
                catch (Exception ex) { output.setText("Error retrieving AI response: " + ex.getMessage()); }
                finally { aiBtn.setEnabled(true); }
            }
        }.execute();
    }

    /** The exact finding backing whichever issue is currently open in the Logger, matched on both
     * header AND issue title (a header can carry more than one possible issue, e.g. Server's
     * version-vs-family split), so the AI never focuses on the wrong one of several findings that
     * share a header. Null when no issue is open (Technology mode, or a raw row picked some other
     * way), the caller falls back to the whole-URL summary in that case. */
    private HeaderFinding findFocusedFinding(UrlAnalysisResult result) {
        if (currentFocusHeader == null || currentFocusIssueName == null) return null;
        for (HeaderFinding f : result.findings) {
            if (f.headerName.equalsIgnoreCase(currentFocusHeader) && f.issueName.equals(currentFocusIssueName)) {
                return f;
            }
        }
        return null;
    }

    /** Resilient lookup for editor search. Group aggregation can occasionally supply a title from
     * its representative while opening another affected response; fall back by issue and then by
     * virtual location, but only ever return an actual observed value. */
    private static HeaderFinding findSearchFinding(UrlAnalysisResult result, String header,
                                                    String issueName) {
        if (result == null) return null;
        for (HeaderFinding f : result.findings) {
            if (f.headerValue == null || f.headerValue.isBlank()) continue;
            if (header != null && issueName != null && f.headerName.equalsIgnoreCase(header)
                    && f.issueName.equals(issueName)) return f;
        }
        if (issueName != null) {
            for (HeaderFinding f : result.findings) {
                if (f.headerValue != null && !f.headerValue.isBlank()
                        && f.issueName.equals(issueName)) return f;
            }
        }
        if (header != null) {
            for (HeaderFinding f : result.findings) {
                if (f.headerValue != null && !f.headerValue.isBlank()
                        && f.headerName.equalsIgnoreCase(header)) return f;
            }
        }
        return null;
    }

    private static String focusedSystemPrompt() {
        return "You are a senior penetration tester writing a single finding for a professional, " +
            "client-facing security assessment report. You are given ONE specific HTTP header " +
            "security finding, already detected by a scanner, do not question whether it applies. " +
            "Write a clear, precise explanation with these sections, in this order: " +
            "1) What it is, a plain-language summary of the issue. " +
            "2) Why it's reported, the underlying security principle or standard this violates. " +
            "3) Real-world impact, concretely what an attacker could do with this, and how that maps " +
            "to the stated severity, don't inflate or downplay it. " +
            "4) Evidence, reference the exact header/value observed on this response. " +
            "5) Remediation, the precise fix, with a concrete corrected header value where applicable. " +
            "For AUTH/COOKIE/API-key discovery findings, treat CYS4 SensitiveDiscoverer " +
            "(https://github.com/CYS4srl/SensitiveDiscoverer) as scanner-methodology context, while " +
            "using the credential provider's official specification as the authority for token format. " +
            "Be direct and technical, like an experienced AppSec consultant, no generic filler.";
    }

    private static String focusedUserContent(UrlAnalysisResult result, HeaderFinding f) {
        StringBuilder sb = new StringBuilder();
        sb.append("URL: ").append(result.url).append("\n");
        sb.append("Finding: ").append(f.issueName).append("\n");
        sb.append("Severity: ").append(f.severity.label).append("  Confidence: ").append(f.confidence.label)
          .append("  Category: ").append(f.category).append("\n");
        sb.append("Header: ").append(f.headerName).append("\n");
        sb.append(f.headerValue != null ? "Observed value: " + f.headerValue + "\n" : "Header is absent from the response.\n");
        sb.append("Scanner evidence: ").append(f.evidence).append("\n");
        sb.append("Scanner description (context, expand on this, don't just repeat it verbatim): ")
          .append(f.description).append("\n");
        if (!result.techFindings.isEmpty()) {
            sb.append("Technology fingerprint (for context only): ");
            sb.append(result.techFindings.stream().map(TechFinding::display)
                    .reduce((a, b) -> a + ", " + b).orElse(""));
            sb.append("\n");
        }
        return sb.toString();
    }

    private static String summarySystemPrompt() {
        return "You are an expert web application security engineer specializing in HTTP security headers, " +
            "cookies and authentication material. For AUTH/COOKIE/API-key discovery, CYS4 " +
            "SensitiveDiscoverer (https://github.com/CYS4srl/SensitiveDiscoverer) is methodology context; " +
            "provider specifications remain authoritative. " +
            "Analyze the findings and give a concise, actionable assessment: " +
            "1) Executive summary (2-3 sentences), 2) Critical issues requiring immediate attention, " +
            "3) Recommended fixes with concrete header values. Be direct and technical.";
    }

    private static String summaryUserContent(UrlAnalysisResult result) {
        StringBuilder findings = new StringBuilder();
        findings.append("URL: ").append(result.url).append("\n\n");
        findings.append("Security findings (").append(result.findings.size()).append(" total):\n\n");
        for (HeaderFinding f : result.findings) {
            findings.append("[").append(f.severity.label.toUpperCase()).append("] ").append(f.issueName).append("\n");
            findings.append("  Header: ").append(f.headerName).append("\n");
            if (f.headerValue != null) findings.append("  Value: ").append(f.headerValue).append("\n");
            findings.append("  ").append(f.description).append("\n\n");
        }
        if (!result.techFindings.isEmpty()) {
            findings.append("Technology fingerprint:\n");
            for (TechFinding tf : result.techFindings) findings.append("  - ").append(tf).append("\n");
        }
        return findings.toString();
    }
}
