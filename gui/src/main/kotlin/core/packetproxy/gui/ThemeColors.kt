/*
 * Copyright 2026 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.gui

import com.formdev.flatlaf.FlatLaf
import java.awt.Color
import javax.swing.UIManager

/**
 * Look-and-feel aware color palette.
 *
 * Values are read from [UIManager] whenever the active look and feel provides them, so the same
 * call site works for both the light and the dark theme. Colors that Swing has no key for are
 * chosen per theme; dark variants are muted so that they stay readable on a dark background.
 */
object ThemeColors {

  fun isDark(): Boolean {
    var laf = UIManager.getLookAndFeel()
    if (laf is FlatLaf) return laf.isDark
    return luminance(panelBackground()) < 0.5
  }

  fun panelBackground(): Color = uiColor("Panel.background", LIGHT_PANEL, DARK_PANEL)

  fun tableBackground(): Color = uiColor("Table.background", LIGHT_PANEL, DARK_CONTENT)

  fun tableAlternateRow(): Color {
    var alternate = UIManager.getColor("Table.alternateRowColor")
    if (alternate != null) return alternate
    var base = tableBackground()
    return if (isDark()) lighten(base, 0.06) else darken(base, 0.06)
  }

  fun tableSelectionBackground(): Color =
    uiColor("Table.selectionBackground", LIGHT_SELECTION, DARK_SELECTION)

  fun tableSelectionForeground(): Color =
    uiColor("Table.selectionForeground", Color.WHITE, WHITE_ISH)

  /** Selection color for rows other than the lead row of a multi-row selection. */
  fun tableSecondarySelectionBackground(): Color =
    blend(tableSelectionBackground(), tableBackground(), 0.45)

  fun textForeground(): Color = uiColor("TextField.foreground", LIGHT_TEXT, DARK_TEXT)

  fun textBackground(): Color = uiColor("TextField.background", LIGHT_PANEL, DARK_CONTENT)

  fun secondaryForeground(): Color =
    uiColor("Label.disabledForeground", Color.GRAY, Color(0x9E, 0x9E, 0x9E))

  fun borderColor(): Color =
    uiColor("Component.borderColor", Color(0x8C, 0x8C, 0x8C), Color(0x5E, 0x63, 0x66))

  fun separatorColor(): Color =
    uiColor("Separator.foreground", Color.LIGHT_GRAY, Color(0x4C, 0x50, 0x52))

  fun hoverBackground(): Color = if (isDark()) Color(0x2F, 0x3A, 0x4A) else Color(0xE6, 0xF0, 0xFF)

  fun sectionTitleForeground(): Color =
    if (isDark()) Color(0x4D, 0xD0, 0xE1) else Color(0x00, 0xEE, 0xD0)

  fun errorForeground(): Color = if (isDark()) Color(0xFF, 0x8A, 0x80) else Color(0xB0, 0x00, 0x20)

  fun errorBackground(): Color = if (isDark()) Color(0x5C, 0x2B, 0x2B) else Color(0xFF, 0xCD, 0xD2)

  fun searchHighlight(): Color = if (isDark()) Color(0x7A, 0x6A, 0x00) else Color.YELLOW

  fun searchCurrentHighlight(): Color = if (isDark()) Color(0x8E, 0x24, 0xAA) else Color.MAGENTA

  fun searchCountBackground(): Color = searchHighlight()

  fun searchCountNotFoundBackground(): Color = if (isDark()) Color(0x4A, 0x4A, 0x4A) else Color.GRAY

  fun searchCountErrorBackground(): Color = if (isDark()) Color(0x8E, 0x24, 0x24) else Color.RED

  fun emphasisForeground(): Color = if (isDark()) Color(0x69, 0xF0, 0xAE) else Color(0, 200, 0)

  fun paramKeyForeground(): Color = if (isDark()) Color(0x82, 0xB1, 0xFF) else Color.BLUE

  fun paramValueForeground(): Color = if (isDark()) Color(0xFF, 0x8A, 0x80) else Color.RED

  fun binarySelectionHighlight(): Color = if (isDark()) Color(0x00, 0x63, 0x6B) else Color.CYAN

  fun diffAddBackground(): Color =
    if (isDark()) Color(0x2E, 0x50, 0x2E) else Color(0x9C, 0xF0, 0x9C)

  fun diffRemoveBackground(): Color =
    if (isDark()) Color(0x5C, 0x2B, 0x2B) else Color(0xFF, 0x9C, 0x9C)

  fun diffChangeBackground(): Color =
    if (isDark()) Color(0x5A, 0x52, 0x1E) else Color(0xF5, 0xF0, 0x9C)

  fun diffDefaultBackground(): Color = textBackground()

  fun historyResendBackground(): Color =
    if (isDark()) Color(0x1E, 0x3A, 0x5F) else Color(0xB8, 0xD9, 0xF0)

  fun historyModifiedBackground(): Color =
    if (isDark()) Color(0x5A, 0x2E, 0x3A) else Color(0xF0, 0xC8, 0xD0)

  /** Picks black or white so that text stays readable on top of [background]. */
  fun foregroundOn(background: Color): Color =
    if (luminance(background) < 0.5) WHITE_ISH else LIGHT_TEXT

  private fun uiColor(key: String, light: Color, dark: Color): Color {
    var color = UIManager.getColor(key)
    if (color != null) return Color(color.red, color.green, color.blue, color.alpha)
    return if (isDarkFallback()) dark else light
  }

  /** [isDark] would recurse through [uiColor]; rely on the look and feel flag only. */
  private fun isDarkFallback(): Boolean {
    var laf = UIManager.getLookAndFeel()
    return laf is FlatLaf && laf.isDark
  }

  private fun blend(from: Color, to: Color, ratio: Double): Color {
    var clamped = ratio.coerceIn(0.0, 1.0)
    return Color(
      mix(from.red, to.red, clamped),
      mix(from.green, to.green, clamped),
      mix(from.blue, to.blue, clamped),
    )
  }

  private fun lighten(color: Color, ratio: Double): Color = blend(color, Color.WHITE, ratio)

  private fun darken(color: Color, ratio: Double): Color = blend(color, Color.BLACK, ratio)

  private fun mix(from: Int, to: Int, ratio: Double): Int =
    (from + (to - from) * ratio).toInt().coerceIn(0, 255)

  private fun luminance(color: Color): Double =
    (0.2126 * color.red + 0.7152 * color.green + 0.0722 * color.blue) / 255.0

  private val LIGHT_PANEL = Color(0xFF, 0xFF, 0xFF)
  private val LIGHT_TEXT = Color(0x1E, 0x1E, 0x1E)
  private val LIGHT_SELECTION = Color(0x5B, 0x7C, 0xFF)
  private val DARK_PANEL = Color(0x3C, 0x3F, 0x41)
  private val DARK_CONTENT = Color(0x2B, 0x2B, 0x2B)
  private val DARK_TEXT = Color(0xBB, 0xBB, 0xBB)
  private val DARK_SELECTION = Color(0x2F, 0x65, 0xCA)
  private val WHITE_ISH = Color(0xF5, 0xF5, 0xF5)
}
