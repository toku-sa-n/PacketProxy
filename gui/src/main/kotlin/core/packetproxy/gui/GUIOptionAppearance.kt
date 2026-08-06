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

import java.awt.Component
import java.awt.Dimension
import java.awt.event.ItemEvent
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultListCellRenderer
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import packetproxy.common.i18nString
import packetproxy.util.errWithStackTrace

class GUIOptionAppearance(private val owner: GUIMain) {

  fun createPanel(): JPanel {
    var panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(createThemeRow())
    panel.alignmentX = Component.LEFT_ALIGNMENT
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), panel.preferredSize.height)
    return panel
  }

  private fun createThemeRow(): JPanel {
    var combo = createThemeComboBox()
    var row = JPanel()
    row.background = ThemeColors.panelBackground()
    row.layout = BoxLayout(row, BoxLayout.X_AXIS)
    row.alignmentX = Component.LEFT_ALIGNMENT
    row.add(JLabel(i18nString("Theme")))
    row.add(Box.createHorizontalStrut(8))
    row.add(combo)
    row.add(Box.createHorizontalGlue())
    row.maximumSize = Dimension(Short.MAX_VALUE.toInt(), row.preferredSize.height)
    return row
  }

  private fun createThemeComboBox(): JComboBox<ThemeMode> {
    var combo = JComboBox(ThemeMode.entries.toTypedArray())
    combo.renderer = ThemeModeRenderer()
    combo.maximumRowCount = combo.itemCount
    combo.selectedItem = owner.themeManager.getMode()
    combo.maximumSize = Dimension(combo.preferredSize.width, combo.minimumSize.height)
    combo.addItemListener { event ->
      if (event.stateChange != ItemEvent.SELECTED) return@addItemListener
      var mode = event.item as? ThemeMode ?: return@addItemListener
      if (mode == owner.themeManager.getMode()) return@addItemListener
      try {
        owner.applyTheme(mode)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    return combo
  }

  private class ThemeModeRenderer : DefaultListCellRenderer() {
    override fun getListCellRendererComponent(
      list: JList<*>?,
      value: Any?,
      index: Int,
      isSelected: Boolean,
      cellHasFocus: Boolean,
    ): Component {
      var label = value as? ThemeMode
      return super.getListCellRendererComponent(
        list,
        label?.localizedLabel() ?: value,
        index,
        isSelected,
        cellHasFocus,
      )
    }
  }
}
