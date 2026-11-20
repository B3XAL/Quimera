package com.b3xal.headeranalyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.b3xal.headeranalyzer.analyzer.CollaboratorInspector;
import com.b3xal.headeranalyzer.analyzer.CollaboratorInspector.CollaboratorHit;
import com.b3xal.headeranalyzer.ui.render.ClipboardUtil;

import static com.b3xal.headeranalyzer.ui.render.ScrollUtil.scrollPane;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Modeless "Collaborator" tool window, opened from Settings. Deliberately passive end to end:
 * "Generate Payload" is a convenience that creates a domain and puts it on the clipboard, nothing
 * is sent anywhere by Quimera. "Check Interactions Now" (and the auto-refresh timer, on by
 * default, same pattern as Burp's own Collaborator client tab) just reads back whatever has
 * already arrived on this session's Collaborator client, however it got triggered, a manual curl
 * against the generated (or the analyst's own) payload, an OOB fired from somewhere else
 * entirely. Picking a row shows the exact incoming HTTP request/response (User-Agent etc.) in
 * Burp's native editors, same widget as everywhere else in Quimera.
 */
public final class CollaboratorDialog extends JDialog {

    private static final String[] COLS = {"Time", "Type", "Client IP", "User-Agent", "Recognized as"};
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final int POLL_INTERVAL_MS = 5000;

    private final CollaboratorInspector inspector;
    private final DefaultTableModel model = new DefaultTableModel(COLS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable table = new JTable(model);
    private List<CollaboratorHit> hits = List.of();

    private final JTextField payloadField = new JTextField();
    private final JLabel statusLabel = new JLabel(" ");
    private final JCheckBox autoRefreshChk = new JCheckBox("Auto-refresh every 5s", true);
    private final Timer pollTimer = new Timer(POLL_INTERVAL_MS, null);

    private final HttpRequestEditor  reqEditor;
    private final HttpResponseEditor respEditor;
    private final JLabel noHttpLabel = new JLabel("No HTTP request captured for this interaction (DNS/SMTP only).", SwingConstants.CENTER);

    private static final String CARD_EMPTY = "empty";
    private static final String CARD_HTTP  = "http";
    private final CardLayout cards = new CardLayout();
    private final JPanel detailCard = new JPanel(cards);

    public CollaboratorDialog(Window owner, MontoyaApi api) {
        super(owner, "Quimera - Collaborator", ModalityType.MODELESS);
        this.inspector  = new CollaboratorInspector(api);
        this.reqEditor  = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.respEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        build();
        setSize(820, 520);
        setLocationRelativeTo(owner);
    }

    private void build() {
        setLayout(new BorderLayout());
        add(buildTopPanel(), BorderLayout.NORTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildTablePanel(), buildDetailPanel());
        split.setResizeWeight(0.45);
        add(split, BorderLayout.CENTER);
    }

    private JPanel buildTopPanel() {
        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(BorderFactory.createEmptyBorder(10, 12, 8, 12));

        JPanel payloadRow = new JPanel(new BorderLayout(6, 0));
        JButton genBtn = new JButton("Generate Payload");
        genBtn.setToolTipText("Creates a fresh Collaborator interaction domain and copies it to the clipboard. "
                + "Quimera does not send anything to it, use it yourself (curl, an OOB header, wherever it's needed).");
        genBtn.addActionListener(e -> generatePayload());
        payloadField.setEditable(false);
        payloadField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JButton copyBtn = new JButton("Copy");
        copyBtn.addActionListener(e -> ClipboardUtil.copyText(payloadField.getText()));
        payloadRow.add(genBtn, BorderLayout.WEST);
        payloadRow.add(payloadField, BorderLayout.CENTER);
        payloadRow.add(copyBtn, BorderLayout.EAST);
        payloadRow.setAlignmentX(LEFT_ALIGNMENT);
        root.add(payloadRow);
        root.add(Box.createRigidArea(new Dimension(0, 8)));

        JPanel checkRow = new JPanel(new BorderLayout(6, 0));
        JPanel checkButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton checkBtn = new JButton("Check Interactions Now");
        checkBtn.setToolTipText("Reads back every interaction already received on this session's Collaborator client.");
        checkBtn.addActionListener(e -> checkInteractions());
        autoRefreshChk.setToolTipText("Polls for new interactions automatically while this window is open, same as Burp's own Collaborator client tab.");
        autoRefreshChk.addActionListener(e -> updatePolling());
        checkButtons.add(checkBtn);
        checkButtons.add(autoRefreshChk);
        statusLabel.setForeground(Color.GRAY);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        checkRow.add(checkButtons, BorderLayout.WEST);
        checkRow.add(statusLabel, BorderLayout.CENTER);
        checkRow.setAlignmentX(LEFT_ALIGNMENT);
        root.add(checkRow);

        pollTimer.addActionListener(e -> checkInteractions());
        pollTimer.setRepeats(true);

        return root;
    }

    /** Starts/stops the auto-refresh timer to match "checkbox checked AND window actually open",
     * on by default so the analyst doesn't have to remember to click Check every time, same UX as
     * Burp's own Collaborator client tab. */
    private void updatePolling() {
        boolean shouldPoll = isVisible() && autoRefreshChk.isSelected();
        if (shouldPoll && !pollTimer.isRunning()) {
            pollTimer.start();
            checkInteractions(); // don't make the analyst wait a full interval for the first read
        } else if (!shouldPoll && pollTimer.isRunning()) {
            pollTimer.stop();
        }
    }

    @Override
    public void setVisible(boolean visible) {
        super.setVisible(visible);
        updatePolling();
    }

    private JPanel buildTablePanel() {
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(22);
        table.setAutoCreateRowSorter(true);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            onRowSelected();
        });
        JPanel p = new JPanel(new BorderLayout());
        p.add(scrollPane(table), BorderLayout.CENTER);
        return p;
    }

    private JPanel buildDetailPanel() {
        detailCard.add(new JPanel(), CARD_EMPTY);

        JPanel httpCard = new JPanel(new BorderLayout());
        JSplitPane reqResp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqEditor.uiComponent(), respEditor.uiComponent());
        reqResp.setResizeWeight(0.5);
        httpCard.add(reqResp, BorderLayout.CENTER);
        detailCard.add(httpCard, CARD_HTTP);

        noHttpLabel.setForeground(Color.GRAY);
        JPanel noHttpCard = new JPanel(new BorderLayout());
        noHttpCard.add(noHttpLabel, BorderLayout.CENTER);
        detailCard.add(noHttpCard, "no-http");

        cards.show(detailCard, CARD_EMPTY);

        JPanel p = new JPanel(new BorderLayout());
        p.add(detailCard, BorderLayout.CENTER);
        return p;
    }

    private void generatePayload() {
        genBtnBusy(true);
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() { return inspector.generatePayload(); }
            @Override protected void done() {
                try {
                    String domain = get();
                    payloadField.setText(domain);
                    ClipboardUtil.copyText(domain);
                    statusLabel.setText("Payload generated and copied to clipboard.");
                } catch (Exception ex) {
                    statusLabel.setText("Failed to generate payload: " + ex.getMessage());
                } finally {
                    genBtnBusy(false);
                }
            }
        }.execute();
    }

    private void genBtnBusy(boolean busy) {
        setCursor(busy ? Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR) : Cursor.getDefaultCursor());
    }

    private void checkInteractions() {
        statusLabel.setText("Checking...");
        new SwingWorker<List<CollaboratorHit>, Void>() {
            @Override protected List<CollaboratorHit> doInBackground() { return inspector.checkInteractions(); }
            @Override protected void done() {
                try {
                    hits = get();
                    model.setRowCount(0);
                    for (CollaboratorHit h : hits) {
                        model.addRow(new Object[]{
                                h.time() != null ? h.time().format(FMT) : "-",
                                h.type(),
                                h.clientIp(),
                                h.userAgent() != null ? h.userAgent() : "-",
                                h.recognizedClient()
                        });
                    }
                    statusLabel.setText(hits.size() + " interaction(s) found.");
                    cards.show(detailCard, CARD_EMPTY);
                } catch (Exception ex) {
                    statusLabel.setText("Failed to check interactions: " + ex.getMessage());
                }
            }
        }.execute();
    }

    private void onRowSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) { cards.show(detailCard, CARD_EMPTY); return; }
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= hits.size()) return;

        CollaboratorHit h = hits.get(modelRow);
        if (h.type() == InteractionType.HTTP && h.requestResponse() != null) {
            if (h.requestResponse().request() != null) reqEditor.setRequest(h.requestResponse().request());
            if (h.requestResponse().response() != null) respEditor.setResponse(h.requestResponse().response());
            cards.show(detailCard, CARD_HTTP);
        } else {
            cards.show(detailCard, "no-http");
        }
    }
}
