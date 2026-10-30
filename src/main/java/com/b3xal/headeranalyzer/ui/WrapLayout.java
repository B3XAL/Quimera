package com.b3xal.headeranalyzer.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;

/** Plain {@link FlowLayout} never grows its reported height when it wraps components onto a
 * second row, so a filter row placed in a BorderLayout.NORTH/SOUTH slot gets clipped to a
 * single row's height as the container narrows, and whatever wrapped past that height is simply
 * invisible instead of pushed down. This recomputes preferred/minimum size by actually simulating
 * the wrap against the container's current width, so the parent layout reserves enough height. */
class WrapLayout extends FlowLayout {
    WrapLayout(int align, int hgap, int vgap) { super(align, hgap, vgap); }

    @Override public Dimension preferredLayoutSize(Container target) { return layoutSize(target); }

    // Deliberately NOT based on the container's current width the way preferredLayoutSize is.
    // JSplitPane bounds how far the divider can be dragged by calling getMinimumSize() on both
    // sides, so a "minimum" that tracks the current width reports "I can never be smaller than I
    // already am", a moving target that re-pins itself on every drag event and makes the divider
    // feel stuck/jittery. The true minimum a wrapping layout ever needs is just the widest single
    // component, the worst case where every component wraps onto its own row.
    @Override public Dimension minimumLayoutSize(Container target) {
        synchronized (target.getTreeLock()) {
            Insets insets = target.getInsets();
            int maxCompW = 0, totalH = 0;
            boolean first = true;
            for (Component c : target.getComponents()) {
                if (!c.isVisible()) continue;
                Dimension d = c.getMinimumSize();
                maxCompW = Math.max(maxCompW, d.width);
                totalH += d.height + (first ? 0 : getVgap());
                first = false;
            }
            return new Dimension(maxCompW + insets.left + insets.right,
                    totalH + getVgap() * 2 + insets.top + insets.bottom);
        }
    }

    private Dimension layoutSize(Container target) {
        synchronized (target.getTreeLock()) {
            int width = target.getWidth();
            if (width == 0) width = Integer.MAX_VALUE;
            Insets insets = target.getInsets();
            int maxw = width - insets.left - insets.right;
            int rowW = 0, rowH = 0, totalH = 0;
            for (Component c : target.getComponents()) {
                if (!c.isVisible()) continue;
                Dimension d = c.getPreferredSize();
                if (rowW + d.width > maxw && rowW > 0) { totalH += rowH + getVgap(); rowW = 0; rowH = 0; }
                rowW += d.width + getHgap();
                rowH = Math.max(rowH, d.height);
            }
            totalH += rowH + getVgap() * 2 + insets.top + insets.bottom;
            return new Dimension(maxw, totalH);
        }
    }
}
