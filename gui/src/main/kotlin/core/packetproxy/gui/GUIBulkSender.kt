package packetproxy.gui

import java.awt.Component
import java.util.function.Consumer
import javax.swing.*
import packetproxy.model.OneShotPacket

class GUIBulkSender private constructor() {
  private var sendPackets = mutableMapOf<Int, OneShotPacket>()
  private var sendPacketIds = mutableMapOf<Int, Int>()
  private var recvPackets = mutableMapOf<Int, OneShotPacket>()
  private lateinit var sendTable: GUIBulkSenderTable
  private lateinit var recvTable: GUIBulkSenderTable
  private lateinit var sendData: GUIBulkSenderData
  private lateinit var recvData: GUIBulkSenderData
  private var selectedSendPacketId = 0
  private var selectedRecvPacketId = 0
  private var sendPacketId = 0

  fun createPanel(): JComponent =
    JSplitPane(JSplitPane.HORIZONTAL_SPLIT).apply {
      add(createSendPanel())
      add(createRecvPanel())
    }

  fun add(packet: OneShotPacket, packetId: Int) {
    packet.setId(sendPacketId)
    sendPackets[sendPacketId] = packet
    sendPacketIds[sendPacketId] = packetId
    sendTable.add(packet)
    sendPacketId++
  }

  private fun createSendPanel(): JComponent {
    sendData =
      GUIBulkSenderData(
        owner,
        GUIBulkSenderData.Type.CLIENT,
        Consumer { sendPackets[selectedSendPacketId]?.setData(it) },
      )
    sendTable =
      GUIBulkSenderTable(
        GUIBulkSenderTable.Type.CLIENT,
        Consumer { id ->
          selectedSendPacketId = id
          sendPackets[id]?.let { sendData.setData(it.getData()) }
        },
      )
    var clear =
      JButton("clear").apply {
        addActionListener {
          sendTable.clear()
          recvTable.clear()
          sendPackets.clear()
          sendPacketIds.clear()
          recvPackets.clear()
          sendData.setData(ByteArray(0))
          recvData.setData(ByteArray(0))
          sendPacketId = 0
        }
      }
    var bottom =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(sendData.createPanel())
        add(JPanel().apply { add(clear) })
      }
    return JSplitPane(JSplitPane.VERTICAL_SPLIT).apply {
      add(sendTable.createPanel())
      add(bottom)
      alignmentX = Component.CENTER_ALIGNMENT
    }
  }

  private fun createRecvPanel(): JComponent {
    recvData =
      GUIBulkSenderData(
        owner,
        GUIBulkSenderData.Type.SERVER,
        Consumer { recvPackets[selectedRecvPacketId]?.setData(it) },
      )
    recvTable =
      GUIBulkSenderTable(
        GUIBulkSenderTable.Type.SERVER,
        Consumer { id ->
          selectedRecvPacketId = id
          recvPackets[id]?.let { recvData.setData(it.getData()) }
        },
      )
    return JSplitPane(JSplitPane.VERTICAL_SPLIT).apply {
      add(recvTable.createPanel())
      add(recvData.createPanel())
      alignmentX = Component.CENTER_ALIGNMENT
    }
  }

  companion object {
    private var instance: GUIBulkSender? = null
    private var owner: JFrame? = null

    @JvmStatic fun getOwner() = owner

    @JvmStatic fun getInstance(): GUIBulkSender = instance ?: GUIBulkSender().also { instance = it }
  }
}
