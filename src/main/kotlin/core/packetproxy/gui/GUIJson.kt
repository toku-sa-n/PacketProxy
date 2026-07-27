package packetproxy.gui

import java.awt.BorderLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextPane
import javax.swing.SwingUtilities
import packetproxy.common.JsonSyntaxHighlighter

class GUIJson : GUIHistoryPanel(), ExtendedTextPane.DataChangedListener {
  private val rawText = RawTextPane()
  private val jsonHighlighter: JsonSyntaxHighlighter
  private val textPanel: JScrollPane
  private val panel: JComponent

  init {
    rawText.isEditable = false
    rawText.addDataChangedListener(this)
    jsonHighlighter = JsonSyntaxHighlighter(rawText.styledDocument)
    textPanel = JScrollPane(rawText)
    panel = JPanel(BorderLayout())
    panel.add(textPanel, BorderLayout.CENTER)
  }

  override fun getTextPane(): JTextPane = rawText

  fun createPanel(): JComponent = panel

  fun appendData(data: ByteArray) {
    val document = rawText.styledDocument
    document.insertString(document.length, String(data, Charsets.UTF_8), null)
    SwingUtilities.invokeLater { jsonHighlighter.applyJsonSyntaxHighlighting() }
  }

  override fun setData(data: ByteArray) {
    rawText.setData(data, true)
    SwingUtilities.invokeLater { jsonHighlighter.applyJsonSyntaxHighlighting() }
  }

  override fun getData(): ByteArray = rawText.getData()

  override fun dataChanged(data: ByteArray) {
    callDataChanged(data)
    SwingUtilities.invokeLater { jsonHighlighter.applyJsonSyntaxHighlighting() }
  }

  override fun setParentTabs(parentTabs: TabSet) {}

  override fun getParentSend(): JButton? = null
}
