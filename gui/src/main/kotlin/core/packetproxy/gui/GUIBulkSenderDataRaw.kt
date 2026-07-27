package packetproxy.gui

import java.awt.BorderLayout
import java.util.function.Consumer
import javax.swing.*
import packetproxy.util.SearchBox

class GUIBulkSenderDataRaw(private var onChanged: Consumer<ByteArray>) :
  RawTextPane.DataChangedListener {
  private var rawText = RawTextPane()
  private var searchBox = SearchBox()
  private var textPanel = JScrollPane(rawText)
  private var panel: JComponent =
    JPanel(BorderLayout()).apply {
      add(textPanel, BorderLayout.CENTER)
      add(searchBox, BorderLayout.SOUTH)
    }

  init {
    rawText.addDataChangedListener(this)
    searchBox.setBaseText(rawText)
  }

  fun createPanel(): JComponent = panel

  fun appendData(data: ByteArray) {
    var document = rawText.getStyledDocument()
    document.insertString(document.length, String(data), null)
  }

  fun setData(data: ByteArray) {
    rawText.setData(data, true)
  }

  fun getData(): ByteArray = rawText.getData()

  override fun dataChanged(data: ByteArray) {
    searchBox.textChanged()
    onChanged.accept(data)
  }
}
