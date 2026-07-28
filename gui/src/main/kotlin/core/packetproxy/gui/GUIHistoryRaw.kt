package packetproxy.gui

import java.awt.BorderLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextPane
import javax.swing.SwingUtilities
import packetproxy.common.JsonSyntaxHighlighter

class GUIHistoryRaw(private val owner: GUIMain) :
  GUIHistoryPanel(), ExtendedTextPane.DataChangedListener {
  private val rawText =
    RawTextPane(
      owner,
      owner.modelServices.fontManager,
      owner.modelServices.charSetUtility,
      owner.coreServices.packetProxyUtility,
    )
  private val jsonHighlighter: JsonSyntaxHighlighter
  private val panel: JComponent
  private var parentTabs: TabSet? = null

  init {
    rawText.addDataChangedListener(this)
    jsonHighlighter = JsonSyntaxHighlighter(rawText.styledDocument)
    panel = JPanel(BorderLayout())
    panel.add(JScrollPane(rawText), BorderLayout.CENTER)
  }

  override fun getTextPane(): JTextPane = rawText

  fun createPanel(): JComponent = panel

  fun appendData(data: ByteArray) {
    val document = rawText.styledDocument
    document.insertString(document.length, String(data, Charsets.UTF_8), null)
    SwingUtilities.invokeLater { jsonHighlighter.applyHighlightingIfJson() }
  }

  override fun setData(data: ByteArray) {
    rawText.setData(data, true)
    SwingUtilities.invokeLater { jsonHighlighter.applyHighlightingIfJson() }
  }

  override fun getData(): ByteArray = rawText.getData()

  override fun setParentTabs(parentTabs: TabSet) {
    this.parentTabs = parentTabs
  }

  override fun getParentSend(): JButton? = parentTabs?.parentSend

  override fun dataChanged(data: ByteArray) {
    callDataChanged(data)
    SwingUtilities.invokeLater { jsonHighlighter.applyHighlightingIfJson() }
  }
}
