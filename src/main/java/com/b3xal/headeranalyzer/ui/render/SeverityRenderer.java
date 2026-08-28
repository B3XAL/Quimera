package com.b3xal.headeranalyzer.ui.render;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.Severity;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class SeverityRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        setHorizontalAlignment(SwingConstants.CENTER);

        if (value instanceof Severity sev) {
            setText(sev.label);
            if (!isSelected) { c.setBackground(sev.color); c.setForeground(Color.WHITE); }
            setFont(getFont().deriveFont(Font.BOLD, 11f));
        } else if (value instanceof Confidence conf) {
            setText(conf.label);
            if (!isSelected) {
                switch (conf) {
                    case CERTAIN   -> { c.setBackground(new Color(39,174,96));  c.setForeground(Color.WHITE); }
                    case FIRM      -> { c.setBackground(new Color(211,127,0));  c.setForeground(Color.WHITE); }
                    case TENTATIVE -> { c.setBackground(new Color(127,140,141)); c.setForeground(Color.WHITE); }
                }
            }
            setFont(getFont().deriveFont(Font.PLAIN, 11f));
        } else {
            if (!isSelected) { c.setBackground(table.getBackground()); c.setForeground(table.getForeground()); }
            setHorizontalAlignment(SwingConstants.LEFT);
        }
        return c;
    }
}
