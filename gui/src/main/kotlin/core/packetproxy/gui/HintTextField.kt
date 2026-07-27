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

import java.awt.Color
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import javax.swing.JTextField
import packetproxy.common.Utils

class HintTextField(hint: String) : JTextField() {
  private var hint: String = hint

  init {
    addFocusListener(
      object : java.awt.event.FocusListener {
        override fun focusGained(event: java.awt.event.FocusEvent) {
          repaint()
        }

        override fun focusLost(event: java.awt.event.FocusEvent) {
          repaint()
        }
      }
    )
  }

  fun setHint(hint: String) {
    this.hint = hint
  }

  fun getHint(): String {
    return hint
  }

  override fun setText(text: String?) {
    super.setText(text)
    repaint()
  }

  override fun paintComponent(graphics: Graphics) {
    super.paintComponent(graphics)
    var graphics2d = graphics as Graphics2D
    if (hasFocus() || text.isNotEmpty() || getHint().isEmpty()) {
      return
    }

    var oldFont = graphics2d.getFont()
    var oldColor = graphics2d.getColor()
    var insets = border.getBorderInsets(this)
    var height = graphics2d.fontMetrics.ascent
    if (Utils.isWindows()) {
      graphics2d.color = Color.LIGHT_GRAY
    } else {
      graphics2d.font = getFont().deriveFont(Font.ITALIC)
      graphics2d.color = Color.GRAY
      graphics2d.setRenderingHint(
        RenderingHints.KEY_TEXT_ANTIALIASING,
        RenderingHints.VALUE_TEXT_ANTIALIAS_ON,
      )
    }
    graphics2d.drawString(getHint(), insets.left, insets.top + height)
    graphics2d.font = oldFont
    graphics2d.color = oldColor
  }
}
