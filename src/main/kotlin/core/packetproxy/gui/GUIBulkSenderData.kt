package packetproxy.gui

import java.util.function.Consumer
import javax.swing.*
import javax.swing.event.ChangeListener
import packetproxy.util.Logging.errWithStackTrace

class GUIBulkSenderData(owner: JFrame, type: Type, private var onChanged: Consumer<ByteArray>) {
  enum class Type {
    CLIENT,
    SERVER,
  }

  private lateinit var mainPanel: JPanel
  private lateinit var dataPane: JTabbedPane
  private lateinit var rawPanel: GUIBulkSenderDataRaw
  private lateinit var binaryPanel: GUIHistoryBinary
  private var showingData: ByteArray? = null

  fun createPanel(): JComponent {
    mainPanel = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
    rawPanel = GUIBulkSenderDataRaw(Consumer { onChanged.accept(it) })
    binaryPanel = GUIHistoryBinary()
    dataPane =
      JTabbedPane().apply {
        addTab("Raw", rawPanel.createPanel())
        addTab("Binary", binaryPanel.createPanel())
        addChangeListener(ChangeListener { update() })
      }
    mainPanel.add(dataPane)
    return mainPanel
  }

  fun setData(data: ByteArray) {
    showingData = data
    update()
  }

  private fun update() {
    var data = showingData ?: return
    try {
      if (dataPane.selectedIndex == 0) rawPanel.setData(data)
      else if (dataPane.selectedIndex == 1) binaryPanel.setData(data)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
