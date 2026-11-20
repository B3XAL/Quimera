package com.b3xal.headeranalyzer.ui;

import com.b3xal.headeranalyzer.analyzer.FieldCheck;
import com.b3xal.headeranalyzer.analyzer.RuleDefinition;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import static com.b3xal.headeranalyzer.ui.render.ScrollUtil.scrollPane;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;

/**
 * Create/edit dialog for a single detection rule: the header it applies to, what happens when
 * the header is missing (if mandatory), and the list of value checks run when it's present.
 */
public final class RuleEditDialog extends JDialog {

    private boolean confirmed = false;
    private final RuleDefinition rule;

    private final JTextField headerField = new JTextField(28);
    private final JCheckBox mandatoryChk = new JCheckBox("Mandatory (flag when this header is absent)");
    private final JTextField missingIssueField = new JTextField(28);
    private final JTextArea  missingDescArea = new JTextArea(3, 28);
    private final JComboBox<Severity> missingSevCombo = new JComboBox<>(Severity.values());
    private final JComboBox<Confidence> missingConfCombo = new JComboBox<>(Confidence.values());
    private final JComboBox<Category> missingCatCombo = new JComboBox<>(Category.values());

    private static final String[] CHECK_COLS = {"Regex", "Trigger", "Issue", "Severity", "Confidence", "Category"};
    private final DefaultTableModel checksModel = new DefaultTableModel(CHECK_COLS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable checksTable = new JTable(checksModel);

    public RuleEditDialog(Window owner, RuleDefinition existing) {
        super(owner, existing == null ? "New Rule" : "Edit Rule", ModalityType.APPLICATION_MODAL);
        this.rule = existing != null ? copy(existing) : fresh();
        build();
        loadFromRule();
    }

    public boolean isConfirmed() { return confirmed; }
    public RuleDefinition getRule() { return rule; }

    private static RuleDefinition fresh() {
        RuleDefinition rd = new RuleDefinition();
        rd.headerName = "";
        rd.builtin = false;
        rd.enabled = true;
        rd.missingSeverity = Severity.LOW;
        rd.missingConfidence = Confidence.FIRM;
        rd.missingCategory = Category.CUSTOM;
        return rd;
    }

    private static RuleDefinition copy(RuleDefinition src) {
        RuleDefinition rd = new RuleDefinition();
        rd.id = src.id;
        rd.headerName = src.headerName;
        rd.enabled = src.enabled;
        rd.builtin = src.builtin;
        rd.mandatory = src.mandatory;
        rd.missingIssueName = src.missingIssueName;
        rd.missingDescription = src.missingDescription;
        rd.missingSeverity = src.missingSeverity != null ? src.missingSeverity : Severity.LOW;
        rd.missingConfidence = src.missingConfidence != null ? src.missingConfidence : Confidence.FIRM;
        rd.missingCategory = src.missingCategory != null ? src.missingCategory : Category.CUSTOM;
        for (RuleDefinition.CheckDefinition c : src.checks) {
            RuleDefinition.CheckDefinition nc = new RuleDefinition.CheckDefinition(
                    c.regex, c.triggerOn, c.issueName, c.description, c.severity, c.confidence, c.category);
            rd.checks.add(nc);
        }
        return rd;
    }

    private void build() {
        setLayout(new BorderLayout(8, 8));
        ((JComponent) getContentPane()).setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 3, 3, 3);
        g.anchor = GridBagConstraints.WEST;
        g.gridx = 0; g.gridy = 0;
        form.add(new JLabel("Header name:"), g);
        g.gridx = 1;
        form.add(headerField, g);

        g.gridx = 0; g.gridy = 1; g.gridwidth = 2;
        form.add(mandatoryChk, g);
        mandatoryChk.addActionListener(e -> updateMandatoryEnabled());

        g.gridwidth = 1;
        g.gridx = 0; g.gridy = 2;
        form.add(new JLabel("Missing-header issue name:"), g);
        g.gridx = 1;
        form.add(missingIssueField, g);

        g.gridx = 0; g.gridy = 3;
        form.add(new JLabel("Missing-header description:"), g);
        g.gridx = 1;
        missingDescArea.setLineWrap(true);
        missingDescArea.setWrapStyleWord(true);
        form.add(scrollPane(missingDescArea), g);

        g.gridx = 0; g.gridy = 4;
        form.add(new JLabel("Missing-header severity:"), g);
        g.gridx = 1;
        JPanel sevRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        sevRow.add(missingSevCombo);
        sevRow.add(new JLabel("Confidence:"));
        sevRow.add(missingConfCombo);
        sevRow.add(new JLabel("Category:"));
        sevRow.add(missingCatCombo);
        form.add(sevRow, g);

        checksTable.setRowHeight(20);
        checksTable.setAutoCreateRowSorter(true);
        JButton addCheck = new JButton("Add Check");
        JButton editCheck = new JButton("Edit Check");
        JButton removeCheck = new JButton("Remove Check");
        addCheck.addActionListener(e -> addOrEditCheck(null));
        editCheck.addActionListener(e -> {
            int row = checksTable.getSelectedRow();
            if (row < 0) return;
            int modelRow = checksTable.convertRowIndexToModel(row);
            addOrEditCheck(rule.checks.get(modelRow));
        });
        removeCheck.addActionListener(e -> {
            int row = checksTable.getSelectedRow();
            if (row < 0) return;
            int modelRow = checksTable.convertRowIndexToModel(row);
            rule.checks.remove(modelRow);
            reloadChecksTable();
        });

        JPanel checkBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        checkBtns.add(addCheck);
        checkBtns.add(editCheck);
        checkBtns.add(removeCheck);

        JPanel checksPanel = new JPanel(new BorderLayout());
        checksPanel.setBorder(BorderFactory.createTitledBorder(
                "Value checks (evaluated when the header IS present)"));
        checksPanel.add(scrollPane(checksTable), BorderLayout.CENTER);
        checksPanel.add(checkBtns, BorderLayout.SOUTH);
        checksPanel.setPreferredSize(new Dimension(560, 180));

        JButton okBtn = new JButton("Save");
        JButton cancelBtn = new JButton("Cancel");
        okBtn.addActionListener(e -> {
            if (saveToRule()) { confirmed = true; dispose(); }
        });
        cancelBtn.addActionListener(e -> dispose());
        JPanel south = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        south.add(okBtn);
        south.add(cancelBtn);

        add(form, BorderLayout.NORTH);
        add(checksPanel, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(getOwner());
    }

    private void addOrEditCheck(RuleDefinition.CheckDefinition existing) {
        CheckEditDialog dlg = new CheckEditDialog(this, existing);
        dlg.setVisible(true);
        if (dlg.isConfirmed()) {
            if (existing == null) rule.checks.add(dlg.getResult());
            else {
                int idx = rule.checks.indexOf(existing);
                if (idx >= 0) rule.checks.set(idx, dlg.getResult());
            }
            reloadChecksTable();
        }
    }

    private void reloadChecksTable() {
        checksModel.setRowCount(0);
        for (RuleDefinition.CheckDefinition c : rule.checks) {
            checksModel.addRow(new Object[]{c.regex, c.triggerOn, c.issueName, c.severity, c.confidence, c.category});
        }
    }

    private void updateMandatoryEnabled() {
        boolean m = mandatoryChk.isSelected();
        missingIssueField.setEnabled(m);
        missingDescArea.setEnabled(m);
        missingSevCombo.setEnabled(m);
        missingConfCombo.setEnabled(m);
        missingCatCombo.setEnabled(m);
    }

    private void loadFromRule() {
        headerField.setText(rule.headerName);
        mandatoryChk.setSelected(rule.mandatory);
        missingIssueField.setText(rule.missingIssueName != null ? rule.missingIssueName : "");
        missingDescArea.setText(rule.missingDescription != null ? rule.missingDescription : "");
        missingSevCombo.setSelectedItem(rule.missingSeverity);
        missingConfCombo.setSelectedItem(rule.missingConfidence);
        missingCatCombo.setSelectedItem(rule.missingCategory);
        reloadChecksTable();
        updateMandatoryEnabled();
    }

    private boolean saveToRule() {
        String header = headerField.getText().trim();
        if (header.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Header name is required.", "Missing field", JOptionPane.WARNING_MESSAGE);
            return false;
        }
        rule.headerName = header;
        rule.mandatory = mandatoryChk.isSelected();
        if (rule.mandatory) {
            String issue = missingIssueField.getText().trim();
            if (issue.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Missing-header issue name is required for mandatory rules.",
                        "Missing field", JOptionPane.WARNING_MESSAGE);
                return false;
            }
            rule.missingIssueName = issue;
            rule.missingDescription = missingDescArea.getText().trim();
            rule.missingSeverity = (Severity) missingSevCombo.getSelectedItem();
            rule.missingConfidence = (Confidence) missingConfCombo.getSelectedItem();
            rule.missingCategory = (Category) missingCatCombo.getSelectedItem();
        } else {
            rule.missingIssueName = null;
            rule.missingDescription = null;
        }
        if (!rule.mandatory && rule.checks.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "A non-mandatory rule with no value checks would never produce a finding.\n" +
                    "Add at least one check, or mark the rule as mandatory.",
                    "Nothing to detect", JOptionPane.WARNING_MESSAGE);
            return false;
        }
        return true;
    }

    // ------ Nested dialog for a single FieldCheck ------------------------------------------------------------------------------------------------

    private static class CheckEditDialog extends JDialog {
        private boolean confirmed = false;
        private RuleDefinition.CheckDefinition result;

        private final JTextField regexField = new JTextField(30);
        private final JComboBox<FieldCheck.TriggerOn> triggerCombo = new JComboBox<>(FieldCheck.TriggerOn.values());
        private final JTextField issueField = new JTextField(30);
        private final JTextArea descArea = new JTextArea(3, 30);
        private final JComboBox<Severity> sevCombo = new JComboBox<>(Severity.values());
        private final JComboBox<Confidence> confCombo = new JComboBox<>(Confidence.values());
        private final JComboBox<Category> catCombo = new JComboBox<>(Category.values());

        CheckEditDialog(Window owner, RuleDefinition.CheckDefinition existing) {
            super(owner, existing == null ? "New Check" : "Edit Check", ModalityType.APPLICATION_MODAL);
            build();
            if (existing != null) {
                regexField.setText(existing.regex);
                triggerCombo.setSelectedItem(existing.triggerOn);
                issueField.setText(existing.issueName);
                descArea.setText(existing.description);
                sevCombo.setSelectedItem(existing.severity);
                confCombo.setSelectedItem(existing.confidence);
                catCombo.setSelectedItem(existing.category);
            } else {
                catCombo.setSelectedItem(Category.CUSTOM);
            }
        }

        boolean isConfirmed() { return confirmed; }
        RuleDefinition.CheckDefinition getResult() { return result; }

        private void build() {
            setLayout(new BorderLayout(8, 8));
            ((JComponent) getContentPane()).setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
            JPanel form = new JPanel(new GridBagLayout());
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(3, 3, 3, 3);
            g.anchor = GridBagConstraints.WEST;

            int row = 0;
            g.gridx = 0; g.gridy = row; form.add(new JLabel("Regex:"), g);
            g.gridx = 1; form.add(regexField, g);
            row++;
            g.gridx = 0; g.gridy = row; form.add(new JLabel("Trigger when:"), g);
            g.gridx = 1; form.add(triggerCombo, g);
            row++;
            g.gridx = 0; g.gridy = row; form.add(new JLabel("Issue name:"), g);
            g.gridx = 1; form.add(issueField, g);
            row++;
            g.gridx = 0; g.gridy = row; form.add(new JLabel("Description:"), g);
            g.gridx = 1;
            descArea.setLineWrap(true); descArea.setWrapStyleWord(true);
            form.add(scrollPane(descArea), g);
            row++;
            g.gridx = 0; g.gridy = row; form.add(new JLabel("Severity / Confidence / Category:"), g);
            g.gridx = 1;
            JPanel r = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            r.add(sevCombo); r.add(confCombo); r.add(catCombo);
            form.add(r, g);

            JButton ok = new JButton("OK");
            JButton cancel = new JButton("Cancel");
            ok.addActionListener(e -> { if (save()) { confirmed = true; dispose(); } });
            cancel.addActionListener(e -> dispose());
            JPanel south = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            south.add(ok); south.add(cancel);

            add(form, BorderLayout.CENTER);
            add(south, BorderLayout.SOUTH);
            pack();
            setLocationRelativeTo(getOwner());
        }

        private boolean save() {
            String regex = regexField.getText().trim();
            if (regex.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Regex is required.", "Missing field", JOptionPane.WARNING_MESSAGE);
                return false;
            }
            try { java.util.regex.Pattern.compile(regex); }
            catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Invalid regex: " + ex.getMessage(), "Regex error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            String issue = issueField.getText().trim();
            if (issue.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Issue name is required.", "Missing field", JOptionPane.WARNING_MESSAGE);
                return false;
            }
            result = new RuleDefinition.CheckDefinition(regex, (FieldCheck.TriggerOn) triggerCombo.getSelectedItem(),
                    issue, descArea.getText().trim(), (Severity) sevCombo.getSelectedItem(),
                    (Confidence) confCombo.getSelectedItem(), (Category) catCombo.getSelectedItem());
            return true;
        }
    }
}
