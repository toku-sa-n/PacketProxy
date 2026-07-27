package packetproxy.gui

import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import javax.swing.*
import packetproxy.model.OneShotPacket
import packetproxy.model.PropertyChangeEventType
import packetproxy.model.ResenderPackets
import packetproxy.util.Logging.errWithStackTrace

class GUIResender private constructor() : PropertyChangeListener {
  private var mainPanel = JPanel()
  private var tabs = CloseButtonTabbedPane()
  private var indexes = mutableListOf<Int>()

  init {
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    mainPanel.add(tabs)
    ResenderPackets.getInstance().addPropertyChangeListener(this)
    loadResenderPackets()
  }

  fun createPanel(): JComponent = mainPanel

  fun addResends(packet: OneShotPacket) {
    var panel = GUIPacketData()
    panel.setOneShotPacket(packet)
    var index = (indexes.lastOrNull() ?: 0) + 1
    indexes.add(index)
    tabs.addTab(index.toString(), panel.createPanel())
    tabs.selectedComponent = panel.createPanel()
  }

  override fun propertyChange(event: PropertyChangeEvent) {
    if (!PropertyChangeEventType.RESENDER_PACKETS.matches(event)) return
    mainPanel.remove(tabs)
    tabs = CloseButtonTabbedPane()
    mainPanel.add(tabs)
    indexes.clear()
    loadResenderPackets()
  }

  private fun loadResenderPackets() {
    try {
      ResenderPackets.getInstance()
        .queryAllOrdered()
        .groupBy { it.getResendsIndex() }
        .forEach { (index, packets) ->
          var panel = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
          packets.forEach { packet ->
            panel.add(
              GUIPacketData().apply { setOneShotPacket(packet.getOneShotPacket()) }.createPanel()
            )
          }
          indexes.add(index)
          tabs.addTab(index.toString(), panel)
        }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  companion object {
    private var instance: GUIResender? = null

    @JvmStatic fun getInstance(): GUIResender = instance ?: GUIResender().also { instance = it }
  }
}
