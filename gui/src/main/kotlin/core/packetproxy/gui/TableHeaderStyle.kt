/*
 * Copyright 2019 DeNA Co., Ltd.
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

import java.awt.BorderLayout
import java.awt.Color
import javax.swing.BorderFactory
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTable
import javax.swing.table.TableCellRenderer

object TableHeaderStyle {
  @JvmStatic
  fun apply(table: JTable, columnCount: Int) {
    var defaultHeaderRenderer = table.tableHeader.defaultRenderer
    var headerRenderer =
      TableCellRenderer { rendererTable, value, isSelected, hasFocus, row, column ->
        var component =
          defaultHeaderRenderer.getTableCellRendererComponent(
            rendererTable,
            value,
            isSelected,
            hasFocus,
            row,
            column,
          )
        if (component !is JLabel) {
          return@TableCellRenderer component
        }

        var panel = JPanel(BorderLayout())
        panel.isOpaque = true
        panel.background = component.background

        var textLabel = JLabel(component.text)
        textLabel.font = component.getFont()
        textLabel.foreground = component.foreground
        var iconLabel = JLabel(component.icon)
        panel.add(textLabel, BorderLayout.WEST)
        panel.add(iconLabel, BorderLayout.EAST)
        panel.border =
          BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 1, Color.LIGHT_GRAY),
            BorderFactory.createEmptyBorder(2, 5, 2, 5),
          )
        panel
      }
    for (index in 0 until columnCount) {
      table.columnModel.getColumn(index).headerRenderer = headerRenderer
    }
  }
}
