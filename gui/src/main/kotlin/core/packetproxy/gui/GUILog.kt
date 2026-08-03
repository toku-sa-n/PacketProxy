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
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextPane
import javax.swing.text.BadLocationException
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import javax.swing.text.StyledDocument
import packetproxy.util.LogLineStyle

class GUILog {
  private val text: JTextPane = PlainTextCopyTextPane()
  private val scrollPane: JScrollPane
  private val mainPanel: JPanel
  private val thread_lock = Any()

  private val timestampAttrs =
    SimpleAttributeSet().apply { StyleConstants.setForeground(this, Color.GRAY) }

  private val errorMessageAttrs =
    SimpleAttributeSet().apply {
      StyleConstants.setForeground(this, Color(180, 40, 40))
      StyleConstants.setBold(this, true)
    }

  init {
    text.isEditable = false
    scrollPane = JScrollPane(text)
    scrollPane.verticalScrollBar.unitIncrement = 16
    mainPanel = JPanel(BorderLayout())
    mainPanel.add(scrollPane, BorderLayout.CENTER)
  }

  fun createPanel(): JComponent = mainPanel

  fun append(s: String?) {
    appendStyled(s, isError = false)
  }

  fun appendErr(s: String?) {
    appendStyled(s, isError = true)
  }

  fun getLogText(): String {
    synchronized(thread_lock) {
      return try {
        val doc: StyledDocument = text.styledDocument
        doc.getText(0, doc.length)
      } catch (_: BadLocationException) {
        ""
      }
    }
  }

  private fun appendStyled(s: String?, isError: Boolean) {
    if (s == null) return
    try {
      synchronized(thread_lock) {
        val doc: StyledDocument = text.styledDocument
        val (timestamp, message) = LogLineStyle.splitLogLine(s)
        if (timestamp.isNotEmpty()) {
          doc.insertString(doc.length, timestamp, timestampAttrs)
        }
        val messageAttrs = if (isError) errorMessageAttrs else null
        doc.insertString(doc.length, message + "\n", messageAttrs)
      }
    } catch (_: BadLocationException) {}
  }
}
