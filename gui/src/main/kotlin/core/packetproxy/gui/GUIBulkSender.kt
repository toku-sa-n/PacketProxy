package packetproxy.gui

import java.awt.BorderLayout
import java.awt.Component
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.function.Consumer
import javax.swing.*
import packetproxy.common.i18nString
import packetproxy.controller.ResendController.ResendWorker
import packetproxy.model.OneShotPacket
import packetproxy.util.err
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
  private val emptyLabel =
    emptyStateLabel(i18nString("Right-click packets in History and select send to Bulk Sender."))
  private lateinit var mainPanel: JPanel
  private lateinit var sendButton: JButton
  private lateinit var deleteButton: JButton
  private lateinit var clearButton: JButton
  private val progressLabel = JLabel().apply { foreground = ThemeColors.secondaryForeground() }

  fun createPanel(): JComponent {
    var splitPane =
      JSplitPane(JSplitPane.HORIZONTAL_SPLIT).apply {
        add(createSendPanel())
        add(createRecvPanel())
      }
    mainPanel =
      JPanel().apply {
        layout = BorderLayout()
        add(emptyLabel, BorderLayout.NORTH)
        add(splitPane, BorderLayout.CENTER)
      }
    updateEmptyState()
    return mainPanel
  }

  fun add(packet: OneShotPacket, packetId: Int) {
    onEDT {
      owner.prepareTab(GUIMain.Panes.BULKSENDER)
      packet.setId(sendPacketId)
      sendPackets[sendPacketId] = packet
      sendPacketIds[sendPacketId] = packetId
      sendTable.add(packet)
      sendPacketId++
      updateEmptyState()
    }
  }

  private fun updateEmptyState() {
    if (!::mainPanel.isInitialized) {
      return
    }
    emptyLabel.setEmptyStateVisible(sendPackets.isEmpty(), mainPanel)
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
        owner,
        GUIBulkSenderTable.Type.CLIENT,
        owner.coreServices.encoderManager.packetSummarizer,
        Consumer { id ->
          selectedSendPacketId = id
          sendPackets[id]?.let { sendData.setData(it.getData()) }
        },
      )
    sendTable.setOnDeleteRequested(Runnable { deleteSelectedPackets() })
    sendButton =
      JButton(i18nString("Send all packets")).apply { addActionListener { sendAllPackets() } }
    var params =
      JButton(i18nString("use params")).apply {
        addActionListener { sendTable.showRegexParamsDialog() }
      }
    deleteButton =
      JButton(i18nString("delete selected packets")).apply {
        addActionListener { deleteSelectedPackets() }
      }
    clearButton = JButton(i18nString("clear")).apply { addActionListener { clearAllPackets() } }
    var bottom =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(sendData.createPanel())
        add(
          JPanel().apply {
            layout = BoxLayout(this, BoxLayout.LINE_AXIS)
            add(sendButton)
            add(params)
            add(deleteButton)
            add(clearButton)
            add(progressLabel)
          }
        )
      }
    return JSplitPane(JSplitPane.VERTICAL_SPLIT).apply {
      add(sendTable.createPanel())
      add(bottom)
      alignmentX = Component.CENTER_ALIGNMENT
    }
  }

  /** 選択されている送信パケットを削除する */
  private fun deleteSelectedPackets() {
    var ids = sendTable.getSelectedPacketIds()
    if (ids.isEmpty()) {
      return
    }
    var message = i18nString("Are you sure you want to delete the %d selected packets?", ids.size)
    if (!confirm(message)) {
      return
    }
    sendTable.deleteSelectedRows()
    for (id in ids) {
      sendPackets.remove(id)
      sendPacketIds.remove(id)
    }
    sendData.setData(ByteArray(0))
    updateEmptyState()
  }

  private fun clearAllPackets() {
    if (sendPackets.isNotEmpty() && !confirm(i18nString("Clear all packets in Bulk Sender?"))) {
      return
    }
    sendTable.clear()
    recvTable.clear()
    sendPackets.clear()
    sendPacketIds.clear()
    recvPackets.clear()
    sendData.setData(ByteArray(0))
    recvData.setData(ByteArray(0))
    sendPacketId = 0
    progressLabel.text = ""
    updateEmptyState()
  }

  private fun confirm(message: String): Boolean =
    JOptionPane.showConfirmDialog(
      owner,
      message,
      i18nString("Bulk Sender"),
      JOptionPane.YES_NO_OPTION,
      JOptionPane.WARNING_MESSAGE,
    ) == JOptionPane.YES_OPTION

  /** 送信中はボタンを無効にして、進捗をラベルに表示する */
  private fun setSending(sending: Boolean, total: Int = 0) {
    onEDT {
      sendButton.isEnabled = !sending
      deleteButton.isEnabled = !sending
      clearButton.isEnabled = !sending
      progressLabel.text =
        if (sending) i18nString("Sending %d packets...", total) else i18nString("Send completed")
    }
  }

  private fun updateProgress(sent: Int, total: Int) {
    onEDT { progressLabel.text = i18nString("Sending %d / %d packets...", sent, total) }
  }

  private fun sendAllPackets() {
    try {
      var regexParams = sendTable.getRegexParams()
      recvTable.clear()
      recvPackets.clear()
      var oneshots = sendPackets.values.toTypedArray()
      if (oneshots.isEmpty()) {
        return
      }
      var resendController = owner.coreServices.resendController
      var packets = owner.modelServices.packets
      var charSetUtility = owner.modelServices.charSetUtility
      setSending(true, oneshots.size)
      sendTable.setStatusForAll(i18nString("sending"))

      if (regexParams.isEmpty()) {
        resendController.resend(
          resendController.run {
            object : ResendWorker(oneshots) {
              override fun process(received: MutableList<OneShotPacket>) {
                try {
                  for (oneshot in received) {
                    recvPackets[oneshot.getId()] = oneshot
                    recvTable.add(oneshot)
                    sendTable.setStatus(oneshot.getId(), i18nString("received"))
                    var packetId = sendPacketIds[oneshot.getId()] ?: continue
                    var packet = packets.query(packetId) ?: continue
                    packet.setResend()
                    packets.update(packet)
                  }
                  updateProgress(recvPackets.size, oneshots.size)
                } catch (e: Exception) {
                  errWithStackTrace(e)
                }
              }

              override fun done() {
                setSending(false)
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
              updateProgress(idx, oneshots.size)
              resendController.resend(
                resendController.run {
                  object : ResendWorker(sendOneshot, 1) {
                    override fun process(received: MutableList<OneShotPacket>) {
                      try {
                        for (recv in received) {
                          recvPackets[recv.getId()] = recv
                          recvTable.add(recv)
                          sendTable.setStatus(recv.getId(), i18nString("received"))
                          var packetId = sendPacketIds[recv.getId()] ?: continue
                          var packet = packets.query(packetId) ?: continue
                          packet.setResend()
                          packets.update(packet)
                          regexParams
                            .filter { it.getPacketId() == idx }
                            .forEach { it.setValue(recv, charSetUtility) }
                        }
                      } catch (e: Exception) {
                        errWithStackTrace(e)
                      }
                    }

                    override fun done() {
                      latch.countDown()
                    }
                  }
                }
              )
              if (!latch.await(RESEND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                err(i18nString("[Error] timed out while waiting for the resend response."))
              }
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          } finally {
            setSending(false)
          }
        }
        .start()
    } catch (e: Exception) {
      errWithStackTrace(e)
      setSending(false)
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
        owner,
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

  companion object {
    private const val RESEND_TIMEOUT_SECONDS = 30L
  }
}
