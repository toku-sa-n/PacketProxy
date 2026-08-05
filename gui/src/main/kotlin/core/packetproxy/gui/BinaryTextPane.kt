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

import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.util.Arrays
import java.util.Base64
import javax.swing.JMenuItem
import javax.swing.JPopupMenu
import packetproxy.common.*
import packetproxy.common.FontManager
import packetproxy.common.Utils
import packetproxy.util.CharSetUtility
import packetproxy.util.PacketProxyUtility
import packetproxy.util.errWithStackTrace

class BinaryTextPane(
  fontManager: FontManager,
  charSetUtility: CharSetUtility,
  packetProxyUtility: PacketProxyUtility,
) : ExtendedTextPane(fontManager, charSetUtility, packetProxyUtility) {
  private val editor = WrapEditorKit(ByteArray(0))
  private var data = ByteArray(0)

  init {
    editorKit = editor
    font = fontManager.getFont()
    var menu = JPopupMenu()
    var titleEncoders = JMenuItem(i18nString("Encoders"))
    titleEncoders.font = fontManager.getUICaptionFont()
    titleEncoders.isEnabled = false
    menu.add(titleEncoders)

    var base64Encoder = JMenuItem(i18nString("Base64 Encoder"))
    base64Encoder.addActionListener {
      try {
        var start = selectionStart / 3
        var end = selectionEnd / 3 + 1
        var selected = Arrays.copyOfRange(getData(), start, end)
        var copyData = String(Base64.getEncoder().encode(selected), Charsets.UTF_8)
        var clipboard = Toolkit.getDefaultToolkit().systemClipboard
        var selection = StringSelection(copyData)
        clipboard.setContents(selection, selection)
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }
    menu.add(base64Encoder)
    addMouseListener(
      object : MouseAdapter() {
        override fun mouseReleased(event: MouseEvent) {
          if (Utils.isWindows() && event.isPopupTrigger) {
            menu.show(event.component, event.x, event.y)
          }
        }

        override fun mousePressed(event: MouseEvent) {
          if (event.isPopupTrigger) {
            menu.show(event.component, event.x, event.y)
          }
        }
      }
    )
  }

  override fun setData(data: ByteArray) {
    this.data = data
  }

  override fun getData(): ByteArray = data
}
