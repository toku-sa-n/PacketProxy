package packetproxy.gui

import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import packetproxy.model.OneShotPacket
import packetproxy.util.Logging.errWithStackTrace

class GUIPacketData {
  private val mainPanel = JPanel()
  private val tabs = TabSet(true, false)
  private var showingPacket: OneShotPacket? = null

  init {
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    mainPanel.add(tabs.tabPanel)
    mainPanel.preferredSize = Dimension(200, 100)
  }

  fun createPanel(): JComponent = mainPanel

  fun getTabs(): TabSet = tabs

  fun update() {
    try {
      tabs.setData(showingPacket?.getData() ?: ByteArray(0))
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  fun setOneShotPacket(oneShot: OneShotPacket?) {
    showingPacket = oneShot
    update()
  }

  fun clear() {
    showingPacket = null
    update()
  }

  fun getOneShotPacket(): OneShotPacket? {
    tabs.getData().let { showingPacket?.setData(it) }
    return showingPacket
  }

  fun setData(data: ByteArray) {
    tabs.raw.setData(data)
  }

  fun appendData(data: ByteArray) {
    tabs.raw.appendData(data)
  }

  fun setParentSend(parentSend: JButton?) {
    tabs.setParentSend(parentSend)
  }
}
