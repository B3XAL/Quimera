package com.b3xal.headeranalyzer.ui.render;

import javax.swing.*;
import java.awt.*;

/**
 * Swing's default JScrollPane vertical unit increment is only a handful of pixels per mouse-wheel
 * notch, painfully slow to scroll through anything taller than a couple of rows. Wrap every
 * scrollable view through here instead of {@code new JScrollPane(view)} directly.
 */
public final class ScrollUtil {

    private ScrollUtil() {}

    private static final int UNIT_INCREMENT = 16;

    public static JScrollPane scrollPane(Component view) {
        JScrollPane sp = new JScrollPane(view);
        sp.getVerticalScrollBar().setUnitIncrement(UNIT_INCREMENT);
        return sp;
    }

    /** For the (rare) case a JScrollPane is built with the multi-arg constructor
     * (explicit vertical/horizontal policy). */
    public static JScrollPane scrollPane(Component view, int vsbPolicy, int hsbPolicy) {
        JScrollPane sp = new JScrollPane(view, vsbPolicy, hsbPolicy);
        sp.getVerticalScrollBar().setUnitIncrement(UNIT_INCREMENT);
        return sp;
    }
}
