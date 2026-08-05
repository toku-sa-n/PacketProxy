package packetproxy.gui

import java.util.function.Consumer
import javax.swing.*
import javax.swing.event.ChangeListener
import packetproxy.common.i18nString
import packetproxy.util.errWithStackTrace

class GUIBulkSenderData(
  private val owner: GUIMain,
  type: Type,
  private var onChanged: Consumer<ByteArray>,
) {
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
    rawPanel = GUIBulkSenderDataRaw(owner, Consumer { onChanged.accept(it) })
    binaryPanel = GUIHistoryBinary(owner)
    dataPane =
      JTabbedPane().apply {
        addTab(i18nString("Raw"), rawPanel.createPanel())
        addTab(i18nString("Binary"), binaryPanel.createPanel())
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
