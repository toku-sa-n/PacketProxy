package packetproxy.gui

import java.awt.Component
import java.util.concurrent.CountDownLatch
import java.util.function.Consumer
import javax.swing.*
import packetproxy.common.i18nString
import packetproxy.controller.ResendController.ResendWorker
import packetproxy.model.OneShotPacket
import packetproxy.util.errWithStackTrace

class GUIBulkSender(private val owner: GUIMain) {
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
        owner.coreServices.encoderManager.packetSummarizer,
        Consumer { id ->
          selectedSendPacketId = id
          sendPackets[id]?.let { sendData.setData(it.getData()) }
        },
      )
    var send =
      JButton(i18nString("Send all packets")).apply { addActionListener { sendAllPackets() } }
    var clear =
      JButton(i18nString("clear")).apply {
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
        add(
          JPanel().apply {
            layout = BoxLayout(this, BoxLayout.LINE_AXIS)
            add(send)
            add(clear)
          }
        )
      }
    return JSplitPane(JSplitPane.VERTICAL_SPLIT).apply {
      add(sendTable.createPanel())
      add(bottom)
      alignmentX = Component.CENTER_ALIGNMENT
    }
  }

  private fun sendAllPackets() {
    try {
      var regexParams = sendTable.getRegexParams()
      recvTable.clear()
      recvPackets.clear()
      var oneshots = sendPackets.values.toTypedArray()
      var resendController = owner.coreServices.resendController
      var packets = owner.modelServices.packets
      var charSetUtility = owner.modelServices.charSetUtility

      if (regexParams.isEmpty()) {
        resendController.resend(
          resendController.run {
            object : ResendWorker(oneshots) {
              override fun process(received: MutableList<OneShotPacket>) {
                try {
                  for (oneshot in received) {
                    recvPackets[oneshot.getId()] = oneshot
                    recvTable.add(oneshot)
                    var packetId = sendPacketIds[oneshot.getId()] ?: continue
                    var packet = packets.query(packetId) ?: continue
                    packet.setResend()
                    packets.update(packet)
                  }
                } catch (e: Exception) {
                  errWithStackTrace(e)
                }
              }
            }
          }
        )
        return
      }

      Thread {
          try {
            for ((idx, oneshot) in oneshots.withIndex()) {
              var latch = CountDownLatch(1)
              var sendOneshot = oneshot
              for (regexParam in regexParams) {
                if (regexParam.getValue() != "") {
                  sendOneshot = regexParam.applyToPacket(sendOneshot, charSetUtility)
                }
              }
              resendController.resend(
                resendController.run {
                  object : ResendWorker(sendOneshot, 1) {
                    override fun process(received: MutableList<OneShotPacket>) {
                      try {
                        for (recv in received) {
                          recvPackets[recv.getId()] = recv
                          recvTable.add(recv)
                          var packetId = sendPacketIds[recv.getId()] ?: continue
                          var packet = packets.query(packetId) ?: continue
                          packet.setResend()
                          packets.update(packet)
                          regexParams
                            .filter { it.getPacketId() == idx }
                            .forEach { it.setValue(recv, charSetUtility) }
                          latch.countDown()
                        }
                      } catch (e: Exception) {
                        errWithStackTrace(e)
                      }
                    }
                  }
                }
              )
              latch.await()
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
        .start()
    } catch (e: Exception) {
      errWithStackTrace(e)
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
        owner.coreServices.encoderManager.packetSummarizer,
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
}
