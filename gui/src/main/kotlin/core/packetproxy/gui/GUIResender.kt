package packetproxy.gui

import java.awt.Component
import java.awt.Dimension
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JSplitPane
import packetproxy.common.i18nString
import packetproxy.controller.ResendController.ResendWorker
import packetproxy.controller.SinglePacketAttackController
import packetproxy.model.OneShotPacket
import packetproxy.model.Packet
import packetproxy.model.PropertyChangeEventType
import packetproxy.util.errWithStackTrace

class GUIResender(private val main: GUIMain) : PropertyChangeListener {
  private val mainPanel = JPanel()
  private var resendsTabs: ResendsCloseButtonTabbedPane = ResendsCloseButtonTabbedPane()
  private val resendsIndexes = mutableListOf<Int>()
  private val emptyLabel =
    emptyStateLabel(i18nString("Right-click a packet in History and select send to Resender."))

  init {
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    mainPanel.add(emptyLabel)
    mainPanel.add(resendsTabs)
    main.modelServices.resenderPackets.addPropertyChangeListener(this)
    loadResenderPackets()
    updateEmptyState()
  }

  fun dispose() {
    main.modelServices.resenderPackets.removePropertyChangeListener(this)
  }

  fun createPanel(): JComponent = mainPanel

  fun addResends(sendPacket: OneShotPacket) {
    try {
      var resends = Resends()
      var resendsIndex = if (resendsIndexes.isEmpty()) 1 else resendsIndexes.last() + 1
      resendsIndexes.add(resendsIndex)
      var component = resends.getComponent()
      resendsTabs.addTab(resendsTabTitle(resendsIndex, sendPacket), component)
      resendsTabs.selectedComponent = component
      resends.addResend(sendPacket, null)
      updateEmptyState()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  /**
   * RESENDER_PACKETSはプロジェクトの切り替え（DBの再接続・再作成）でしか通知されず、保持しているパケットが総入れ替えになるため、
   * タブを作り直す。編集中のフォーカスを壊す通常操作では通知されない。
   */
  override fun propertyChange(event: PropertyChangeEvent) {
    if (!PropertyChangeEventType.RESENDER_PACKETS.matches(event)) return
    onEDT {
      try {
        mainPanel.remove(resendsTabs)
        resendsTabs = ResendsCloseButtonTabbedPane()
        mainPanel.add(resendsTabs)
        resendsIndexes.clear()
        loadResenderPackets()
        updateEmptyState()
        mainPanel.revalidate()
        mainPanel.repaint()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  private fun updateEmptyState() {
    emptyLabel.setEmptyStateVisible(resendsTabs.tabCount == 0, mainPanel)
  }

  private fun loadResenderPackets() {
    try {
      var resenderPackets = main.modelServices.resenderPackets.queryAllOrdered()
      var beforeResendsIndex = -1
      var resends: Resends? = null
      var i = 0
      while (i < resenderPackets.size) {
        var resenderPacket = resenderPackets[i]
        var resendsIndex = resenderPacket.getResendsIndex()
        var resendIndex = resenderPacket.getResendIndex()

        if (resendsIndex != beforeResendsIndex) {
          resends = Resends()
          var title = resendsTabTitle(resendsIndex, resenderPacket.getOneShotPacket())
          resendsTabs.addTab(title, resends.getComponent())
          resendsIndexes.add(resendsIndex)
          beforeResendsIndex = resendsIndex
        }

        var currentResends = resends ?: continue
        var resend = Resend(currentResends)
        currentResends.resendTabs.addTab(resendIndex.toString(), resend.getComponent())
        currentResends.resendIndexes.add(resendIndex)

        if (resendIndex == 1) {
          resend.setOneShotPacket(resenderPacket.getOneShotPacket(), null)
        } else if (i + 1 < resenderPackets.size) {
          var nextResenderPacket = resenderPackets[i + 1]
          if (resenderPacket.getDirection() == Packet.Direction.CLIENT) {
            resend.setOneShotPacket(
              resenderPacket.getOneShotPacket(),
              nextResenderPacket.getOneShotPacket(),
            )
          } else {
            resend.setOneShotPacket(
              nextResenderPacket.getOneShotPacket(),
              resenderPacket.getOneShotPacket(),
            )
          }
          i++
        } else {
          resend.setOneShotPacket(resenderPacket.getOneShotPacket(), null)
        }
        i++
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  /** タブ名を "1: GET /login" のようにする。HTTPリクエストとして解釈できない場合は番号だけにする。 */
  private fun resendsTabTitle(resendsIndex: Int, packet: OneShotPacket?): String {
    var summary = requestSummary(packet) ?: return resendsIndex.toString()
    return "$resendsIndex: $summary"
  }

  private fun requestSummary(packet: OneShotPacket?): String? {
    var data = packet?.getData() ?: return null
    if (data.isEmpty()) return null
    var firstLine =
      String(data, Charsets.ISO_8859_1).lineSequence().firstOrNull()?.trim() ?: return null
    var tokens = firstLine.split(" ")
    if (tokens.size < 2) return null
    var method = tokens[0]
    if (!HTTP_METHODS.contains(method)) return null
    return "$method ${shortPath(tokens[1])}"
  }

  /** パスは末尾の要素だけを表示する。タブ幅を取り過ぎないよう長い場合は省略する。 */
  private fun shortPath(path: String): String {
    var trimmed = path.substringBefore('?').substringBefore('#').trimEnd('/')
    var lastElement = trimmed.substringAfterLast('/')
    if (lastElement.isEmpty()) return "/"
    var name = "/$lastElement"
    if (name.length <= MAX_TAB_PATH_LENGTH) return name
    return name.take(MAX_TAB_PATH_LENGTH) + "..."
  }

  private inner class ResendsCloseButtonTabbedPane : CloseButtonTabbedPane() {
    override fun removeTabAt(index: Int) {
      super.removeTabAt(index)
      try {
        var resendsIndex = resendsIndexes.removeAt(index)
        main.modelServices.resenderPackets.deleteResends(resendsIndex)
        updateEmptyState()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  private inner class Resends {
    private val mainPanel = JPanel()
    val resendTabs: CloseButtonTabbedPane = ResendCloseButtonTabbedPane()
    val resendIndexes = mutableListOf<Int>()

    init {
      mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
      mainPanel.add(resendTabs)
    }

    fun addResend(sendPacket: OneShotPacket, recvPacket: OneShotPacket?) {
      var resend = Resend(this)
      var resendIndex = if (resendIndexes.isEmpty()) 1 else resendIndexes.last() + 1
      resendIndexes.add(resendIndex)
      var component = resend.getComponent()
      resendTabs.addTab(resendIndex.toString(), component)
      resendTabs.selectedComponent = component
      resend.setOneShotPacket(sendPacket, recvPacket)

      var resendsIndex = resendsIndexes[resendsTabs.selectedIndex]
      main.modelServices.resenderPackets.createResend(
        sendPacket.getResenderPacket(resendsIndex, resendIndex)
      )
      if (recvPacket != null) {
        main.modelServices.resenderPackets.createResend(
          recvPacket.getResenderPacket(resendsIndex, resendIndex)
        )
      }
    }

    fun getComponent(): JComponent = mainPanel

    private inner class ResendCloseButtonTabbedPane : CloseButtonTabbedPane() {
      override fun removeTabAt(index: Int) {
        super.removeTabAt(index)
        try {
          var resendIndex = resendIndexes.removeAt(index)
          var resendsIndex = resendsIndexes[resendsTabs.selectedIndex]
          main.modelServices.resenderPackets.deleteResend(resendsIndex, resendIndex)
        } catch (e: Exception) {
          errWithStackTrace(e)
        }
      }
    }
  }

  private inner class Resend(private val resends: Resends) : PropertyChangeListener {
    private val serverNamePanel = GUIServerNamePanel()
    private var sendSaved: OneShotPacket? = null
    private var recvSaved: OneShotPacket? = null
    private val sendPanel = GUIPacketData(main)
    private val recvPanel = GUIPacketData(main)
    private val splitPanel =
      JSplitPane(JSplitPane.HORIZONTAL_SPLIT).apply {
        background = ThemeColors.panelBackground()
        add(sendPanel.createPanel())
        add(recvPanel.createPanel())
        alignmentX = Component.CENTER_ALIGNMENT
        resizeWeight = 0.5
      }
    private val resendButton =
      JButton(i18nString("send")).apply {
        toolTipText = i18nString("Send this packet once")
        addActionListener { sendOnce() }
      }
    private val resendMultipleButton =
      JButton(i18nString("send x N...")).apply {
        toolTipText = i18nString("Send this packet the specified number of times")
        addActionListener { sendMultiple() }
      }
    private val attackButton =
      JButton(i18nString("send x N... (single-packet attack)")).apply {
        toolTipText =
          i18nString("Send the specified number of requests packed into a single TCP packet")
        addActionListener { sendSinglePacketAttack() }
      }
    private val mainPanel =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(serverNamePanel)
        add(splitPanel)
        add(
          JPanel().apply {
            add(resendButton)
            add(resendMultipleButton)
            add(attackButton)
            // ボタンが潰れないように、実際に必要な高さを上限にする
            maximumSize = Dimension(Short.MAX_VALUE.toInt(), preferredSize.height)
          }
        )
      }
    private var sendableTabSelected = true
    private var sending = false

    init {
      sendPanel.getTabs().addPropertyChangeListener(this)
      sendPanel.setParentSend(resendButton)
    }

    fun getComponent(): JComponent = mainPanel

    fun setOneShotPacket(sendPacket: OneShotPacket?, recvPacket: OneShotPacket?) {
      sendSaved = sendPacket?.clone() as OneShotPacket?
      recvSaved = recvPacket?.clone() as OneShotPacket?
      sendPanel.setOneShotPacket(sendPacket)
      recvPanel.setOneShotPacket(recvPacket)
      serverNamePanel.updateServerName(sendPacket)
    }

    private fun rollback() {
      sendPanel.setOneShotPacket(sendSaved?.clone() as OneShotPacket?)
      recvPanel.setOneShotPacket(recvSaved?.clone() as OneShotPacket?)
    }

    private fun sendOnce() {
      if (sending) return
      try {
        var sendPacket = sendPanel.getOneShotPacket() ?: return
        var resendController = main.coreServices.resendController
        setSending(true)
        resendController.resend(
          resendController.run {
            object : ResendWorker(sendPacket, 1) {
              override fun process(packets: MutableList<OneShotPacket>) {
                try {
                  var recvPacket = packets[0]
                  recvPanel.setOneShotPacket(recvPacket)
                  resends.addResend(sendPacket, recvPacket)
                  rollback()
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
      } catch (e: Exception) {
        setSending(false)
        errWithStackTrace(e)
      }
    }

    private fun sendMultiple() {
      if (sending) return
      try {
        var sendPacket = sendPanel.getOneShotPacket() ?: return
        var count = askSendCount(main, DEFAULT_SEND_COUNT) ?: return
        var resendController = main.coreServices.resendController
        setSending(true)
        resendController.resend(
          resendController.run {
            object : ResendWorker(sendPacket, count) {
              override fun done() {
                setSending(false)
              }
            }
          }
        )
        clearLog()
        showLog(i18nString("Check the result in the History window!"))
        rollback()
      } catch (e: Exception) {
        setSending(false)
        errWithStackTrace(e)
      }
    }

    private fun sendSinglePacketAttack() {
      if (sending) return
      try {
        var sendPacket = sendPanel.getOneShotPacket() ?: return
        var count = askSendCount(main, DEFAULT_SEND_COUNT) ?: return
        setSending(true)
        try {
          SinglePacketAttackController(
              sendPacket,
              main.coreServices.duplexFactory,
              main.coreServices.encoderManager,
            )
            .attack(count)
        } finally {
          setSending(false)
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    /** 送信中は二重送信を防ぐためにボタンを無効化する。 */
    private fun setSending(value: Boolean) {
      sending = value
      updateSendButtons()
    }

    private fun updateSendButtons() {
      var sendable = sendableTabSelected && !sending
      resendButton.isEnabled = sendable
      resendMultipleButton.isEnabled = sendable
      attackButton.isEnabled = sendable
    }

    private fun showLog(log: String) {
      recvPanel.appendData("$log\n".toByteArray())
    }

    private fun clearLog() {
      recvPanel.setData(ByteArray(0))
    }

    override fun propertyChange(event: PropertyChangeEvent) {
      if (event.source !is TabSet || !PropertyChangeEventType.SELECTED_INDEX.matches(event)) {
        return
      }
      var selectedIndex = event.newValue as Int
      sendableTabSelected = selectedIndex != JSON_TAB_INDEX
      updateSendButtons()
    }
  }

  companion object {
    private const val DEFAULT_SEND_COUNT = 20
    private const val MAX_TAB_PATH_LENGTH = 20
    private const val JSON_TAB_INDEX = 2
    private val HTTP_METHODS =
      setOf("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT")
  }
}
