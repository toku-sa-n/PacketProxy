package packetproxy.gui

import java.awt.BorderLayout
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.*
import packetproxy.common.Range
import packetproxy.common.i18nString
import packetproxy.controller.ResendController.ResendWorker
import packetproxy.model.OneShotPacket
import packetproxy.util.err
import packetproxy.util.errWithStackTrace
import packetproxy.vulchecker.VulCheckPattern
import packetproxy.vulchecker.VulChecker

class GUIVulCheckTab(
  private val main: GUIMain,
  vulChecker: VulChecker,
  packet: OneShotPacket,
  range: Range,
) {
  private var name = vulChecker.getName()
  private var manager = GUIVulCheckManager(vulChecker, packet, range)
  private var recvPackets = mutableMapOf<Int, OneShotPacket>()
  private lateinit var sendTable: GUIVulCheckSendTable
  private lateinit var recvTable: GUIVulCheckRecvTable
  private lateinit var sendData: TabSet
  private lateinit var recvData: TabSet
  private var selectedGeneratorName = ""
  private var recvPacketId = 0
  private lateinit var sendButton: JButton
  private lateinit var sendAllButton: JButton
  private val progressLabel = JLabel().apply { foreground = ThemeColors.secondaryForeground() }

  /** タブのタイトルに使うチェッカー名 */
  val checkerName: String
    get() = name

  fun createPanel(): JComponent {
    var split =
      JSplitPane(JSplitPane.HORIZONTAL_SPLIT).apply {
        add(createSendPanel())
        add(createRecvPanel())
      }
    sendTable.apply {
      manager.getGenerators().forEach {
        add(
          it.getName(),
          manager.findVulCheckPattern(it.getName()).getPacket(),
          manager.isEnabled(it.getName()),
        )
      }
    }
    return JPanel().apply {
      layout = BoxLayout(this, BoxLayout.Y_AXIS)
      background = ThemeColors.panelBackground()
      add(
        JLabel(name).apply {
          foreground = ThemeColors.emphasisForeground()
          font = main.modelServices.fontManager.getUICaptionFont()
        }
      )
      add(split)
    }
  }

  private fun createSendPanel(): JComponent {
    sendData = TabSet(main, true, false)
    sendTable =
      GUIVulCheckSendTable(
        main.coreServices.encoderManager.packetSummarizer,
        { generator ->
          if (selectedGeneratorName.isNotEmpty() && selectedGeneratorName != generator) {
            var previous = manager.findVulCheckPattern(selectedGeneratorName)
            var previousPacket = previous.getPacket()
            var edited = sendData.getData()
            if (!previousPacket.getData().contentEquals(edited)) {
              previousPacket.setData(edited)
              manager.saveVulCheckPattern(
                selectedGeneratorName,
                VulCheckPattern(previous.getName(), previousPacket, null),
              )
            }
          }
          selectedGeneratorName = generator
          manager.findVulCheckPattern(generator).let {
            sendData.setData(it.getPacket().getData(), it.getRange())
          }
        },
        { generator ->
          manager.setEnabled(generator, true)
          manager.findVulCheckPattern(generator).let {
            sendData.setData(it.getPacket().getData(), it.getRange())
            sendTable.setRow(generator, it.getPacket())
          }
          true
        },
        { generator ->
          manager.setEnabled(generator, false)
          true
        },
      )
    sendButton = JButton(i18nString("send")).apply { addActionListener { sendSelected() } }
    sendAllButton = JButton(i18nString("send all")).apply { addActionListener { sendAllEnabled() } }
    var bottom =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(sendData.tabPanel)
        add(
          JPanel().apply {
            layout = BoxLayout(this, BoxLayout.LINE_AXIS)
            add(sendButton)
            add(sendAllButton)
            add(progressLabel)
          }
        )
      }
    return JSplitPane(JSplitPane.VERTICAL_SPLIT).apply {
      add(sendTable.createPanel())
      add(bottom)
      dividerLocation = 200
    }
  }

  private fun sendSelected() {
    try {
      var generatorName = sendTable.selectedGeneratorName
      if (generatorName.isEmpty() || !manager.isEnabled(generatorName)) {
        return
      }
      var pattern = manager.findVulCheckPattern(generatorName)
      var packet = pattern.getPacket()
      var data = manager.extractMacro(generatorName, sendData.getData())
      if (data.isEmpty()) {
        return
      }
      packet.setData(data)
      var sentTime = Date()
      var resendController = main.coreServices.resendController
      resendController.resend(
        resendController.run {
          object : ResendWorker(packet, 1) {
            override fun process(oneshots: MutableList<OneShotPacket>) {
              addReceived(pattern.getName(), oneshots, sentTime)
            }
          }
        }
      )
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  /** 送信中はボタンを無効にして、進捗をラベルに表示する */
  private fun setSending(sending: Boolean, total: Int = 0) {
    onEDT {
      sendButton.isEnabled = !sending
      sendAllButton.isEnabled = !sending
      progressLabel.text =
        if (sending) i18nString("Sending %d packets...", total) else i18nString("Send completed")
    }
  }

  private fun sendAllEnabled() {
    var patterns = manager.getAllEnabledVulCheckPattern()
    if (patterns.isEmpty()) {
      return
    }
    var resendController = main.coreServices.resendController
    setSending(true, patterns.size)
    Thread {
        for ((index, pattern) in patterns.withIndex()) {
          try {
            onEDT {
              progressLabel.text = i18nString("Sending %d / %d packets...", index, patterns.size)
            }
            var sentTime = Date()
            var packet = pattern.getPacket()
            packet.setData(manager.extractMacro(pattern.getName(), packet.getData()))
            var latch = CountDownLatch(1)
            resendController.resend(
              resendController.run {
                object : ResendWorker(packet, 1) {
                  override fun process(oneshots: MutableList<OneShotPacket>) {
                    addReceived(pattern.getName(), oneshots, sentTime)
                  }

                  override fun done() {
                    latch.countDown()
                  }
                }
              }
            )
            if (!latch.await(SEND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
              err(i18nString("[Error] timed out while waiting for the resend response."))
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
        setSending(false)
      }
      .start()
  }

  private fun addReceived(name: String, oneshots: List<OneShotPacket>, sentTime: Date) {
    var recvTime = Date()
    onEDT {
      try {
        for (oneshot in oneshots) {
          recvPackets[recvPacketId] = oneshot
          recvTable.add(recvPacketId, name, oneshot, recvTime.time - sentTime.time)
          recvPacketId++
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  private fun createRecvPanel(): JComponent {
    recvData = TabSet(main, true, false)
    recvTable =
      GUIVulCheckRecvTable(main.coreServices.encoderManager.packetSummarizer) { id ->
        recvPackets[id]?.let { recvData.setData(it.getData()) }
      }
    var clearButton =
      JButton(i18nString("clear")).apply {
        addActionListener {
          recvTable.clear()
          recvPackets.clear()
          recvPacketId = 0
          recvData.setData(ByteArray(0))
        }
      }
    var top =
      JPanel().apply {
        layout = BorderLayout()
        add(recvTable.createPanel(), BorderLayout.CENTER)
        add(
          JPanel().apply {
            layout = BoxLayout(this, BoxLayout.LINE_AXIS)
            add(clearButton)
          },
          BorderLayout.SOUTH,
        )
      }
    return JSplitPane(JSplitPane.VERTICAL_SPLIT).apply {
      add(top)
      add(recvData.tabPanel)
      dividerLocation = 200
    }
  }

  companion object {
    private const val SEND_TIMEOUT_SECONDS = 30L
  }
}
