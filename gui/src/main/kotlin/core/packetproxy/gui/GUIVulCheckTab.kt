package packetproxy.gui

import java.awt.Color
import javax.swing.*
import packetproxy.common.Range
import packetproxy.model.OneShotPacket
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
    return JSplitPane(JSplitPane.VERTICAL_SPLIT).apply {
      add(sendTable.createPanel())
      add(sendData.tabPanel)
      dividerLocation = 200
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

  companion object {
    private var owner: JFrame? = null

    @JvmStatic fun getOwner(): JFrame? = owner
  }
}
