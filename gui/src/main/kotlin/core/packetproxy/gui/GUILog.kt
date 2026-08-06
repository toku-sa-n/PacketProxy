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
import java.awt.Dimension
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextPane
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.text.AttributeSet
import javax.swing.text.BadLocationException
import javax.swing.text.DefaultCaret
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import javax.swing.text.StyledDocument
import packetproxy.common.i18nString
import packetproxy.util.LogLineStyle

class GUILog {
  private val text: JTextPane = PlainTextCopyTextPane()
  private val scrollPane: JScrollPane
  private val mainPanel: JPanel
  private val thread_lock = Any()
  private val structuredEntries = ArrayDeque<packetproxy.util.StructuredLogEntry>()
  private val maxStructuredEntries = 5000
  private val filterField = HintTextField(i18nString("Filter"))
  private val autoScrollToggle = JCheckBox(i18nString("Auto scroll"), true)
  private val clearButton = JButton(i18nString("Clear"))

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
    mainPanel.add(createToolBar(), BorderLayout.NORTH)
    mainPanel.add(scrollPane, BorderLayout.CENTER)
    applyAutoScroll()
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

  fun getStructuredEntries(): List<packetproxy.util.StructuredLogEntry> {
    synchronized(thread_lock) {
      return structuredEntries.toList()
    }
  }

  private fun createToolBar(): JComponent {
    filterField.toolTipText = i18nString("Show only the log lines that contain this text")
    filterField.maximumSize = Dimension(Short.MAX_VALUE.toInt(), filterField.preferredSize.height)
    filterField.document.addDocumentListener(
      object : DocumentListener {
        override fun insertUpdate(event: DocumentEvent) = rerender()

        override fun removeUpdate(event: DocumentEvent) = rerender()

        override fun changedUpdate(event: DocumentEvent) = rerender()
      }
    )
    autoScrollToggle.toolTipText = i18nString("Scroll to the newest log line automatically")
    autoScrollToggle.addActionListener { applyAutoScroll() }
    clearButton.toolTipText = i18nString("Remove all the log lines")
    clearButton.addActionListener { clear() }

    var bar = JPanel()
    bar.layout = BoxLayout(bar, BoxLayout.X_AXIS)
    bar.border = BorderFactory.createEmptyBorder(4, 4, 4, 4)
    bar.add(filterField)
    bar.add(Box.createHorizontalStrut(8))
    bar.add(autoScrollToggle)
    bar.add(Box.createHorizontalStrut(8))
    bar.add(clearButton)
    return bar
  }

  private fun applyAutoScroll() {
    var caret = text.caret as? DefaultCaret ?: return
    if (!autoScrollToggle.isSelected) {
      caret.updatePolicy = DefaultCaret.NEVER_UPDATE
      return
    }
    caret.updatePolicy = DefaultCaret.ALWAYS_UPDATE
    text.caretPosition = text.document.length
  }

  private fun clear() {
    synchronized(thread_lock) {
      structuredEntries.clear()
      removeAllText()
    }
  }

  /** フィルタが変わったときは、保持している範囲のログから表示を組み立て直す。 */
  private fun rerender() {
    synchronized(thread_lock) {
      removeAllText()
      structuredEntries
        .filter { matchesFilter(it.rawLine) }
        .forEach { insertLine(it.rawLine, it.level == ERROR_LEVEL) }
    }
  }

  private fun appendStyled(s: String?, isError: Boolean) {
    if (s == null) return
    synchronized(thread_lock) {
      val level = if (isError) ERROR_LEVEL else INFO_LEVEL
      structuredEntries.addLast(packetproxy.util.StructuredLogEntry(s, level))
      while (structuredEntries.size > maxStructuredEntries) {
        structuredEntries.removeFirst()
      }
      if (!matchesFilter(s)) return
      insertLine(s, isError)
    }
  }

  private fun insertLine(line: String, isError: Boolean) {
    try {
      val doc: StyledDocument = text.styledDocument
      val (timestamp, message) = LogLineStyle.splitLogLine(line)
      if (timestamp.isNotEmpty()) {
        doc.insertString(doc.length, timestamp, timestampAttrs)
      }
      val messageAttrs: AttributeSet? = if (isError) errorMessageAttrs else null
      doc.insertString(doc.length, message + "\n", messageAttrs)
    } catch (_: BadLocationException) {}
  }

  private fun removeAllText() {
    try {
      val doc: StyledDocument = text.styledDocument
      doc.remove(0, doc.length)
    } catch (_: BadLocationException) {}
  }

  private fun matchesFilter(line: String): Boolean {
    var keyword = filterField.text ?: ""
    if (keyword.isEmpty()) return true
    return line.contains(keyword, ignoreCase = true)
  }

  companion object {
    private const val INFO_LEVEL = "info"
    private const val ERROR_LEVEL = "error"
  }
}
