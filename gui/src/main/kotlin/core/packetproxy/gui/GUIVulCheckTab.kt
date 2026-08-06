package packetproxy.gui

import java.awt.Color
import java.util.Date
import java.util.concurrent.CompletableFuture
import javax.swing.*
import packetproxy.common.Range
import packetproxy.common.i18nString
import packetproxy.controller.ResendController.ResendWorker
import packetproxy.model.OneShotPacket
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
      background = Color.WHITE
      add(
        JLabel(name).apply {
          foreground = Color(0, 200, 0)
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
    var sendButton = JButton(i18nString("send")).apply { addActionListener { sendSelected() } }
    var sendAllButton =
      JButton(i18nString("send all")).apply { addActionListener { sendAllEnabled() } }
    var bottom =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(sendData.tabPanel)
        add(
          JPanel().apply {
            layout = BoxLayout(this, BoxLayout.LINE_AXIS)
            add(sendButton)
            add(sendAllButton)
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
      if (data == null || data.isEmpty()) {
        return
      }
      packet.setData(data)
      var sentTime = Date()
      var resendController = main.coreServices.resendController
      resendController.resend(
        resendController.run {
          object : ResendWorker(packet, 1) {
            override fun process(oneshots: MutableList<OneShotPacket>) {
              var recvTime = Date()
              try {
                for (oneshot in oneshots) {
                  recvPackets[recvPacketId] = oneshot
                  recvTable.add(
                    recvPacketId,
                    pattern.getName(),
                    oneshot,
                    recvTime.time - sentTime.time,
                  )
                  recvPacketId++
                }
              } catch (e: Exception) {
                errWithStackTrace(e)
              }
            }
          }
        }
      )
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun sendAllEnabled() {
    try {
      var future = CompletableFuture.completedFuture("send all packets")
      var resendController = main.coreServices.resendController
      for (pattern in manager.getAllEnabledVulCheckPattern()) {
        future =
          future.thenApplyAsync { arg ->
            try {
              var sentTime = Date()
              var packet = pattern.getPacket()
              packet.setData(manager.extractMacro(pattern.getName(), packet.getData()))
              resendController.resend(
                resendController.run {
                  object : ResendWorker(packet, 1) {
                    override fun process(oneshots: MutableList<OneShotPacket>) {
                      var recvTime = Date()
                      try {
                        for (res in oneshots) {
                          recvPackets[recvPacketId] = res
                          recvTable.add(
                            recvPacketId,
                            pattern.getName(),
                            res,
                            recvTime.time - sentTime.time,
                          )
                          recvPacketId++
                        }
                      } catch (e: Exception) {
                        errWithStackTrace(e)
                      }
                    }
                  }
                }
              )
            } catch (e: Exception) {
              errWithStackTrace(e)
            }
            arg
          }
        future =
          future.thenApplyAsync { arg ->
            try {
              Thread.sleep(100)
            } catch (e: Exception) {
              errWithStackTrace(e)
            }
            arg
          }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun createRecvPanel(): JComponent {
    recvData = TabSet(main, true, false)
    recvTable =
      GUIVulCheckRecvTable(main.coreServices.encoderManager.packetSummarizer) { id ->
        recvPackets[id]?.let { recvData.setData(it.getData()) }
      }
    return JSplitPane(JSplitPane.VERTICAL_SPLIT).apply {
      add(recvTable.createPanel())
      add(recvData.tabPanel)
      dividerLocation = 200
    }
  }
}
