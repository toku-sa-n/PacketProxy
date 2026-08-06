package packetproxy.gui

import java.awt.Color
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

  init {
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    mainPanel.add(resendsTabs)
    main.modelServices.resenderPackets.addPropertyChangeListener(this)
    loadResenderPackets()
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
      resendsTabs.addTab(resendsIndex.toString(), component)
      resendsTabs.selectedComponent = component
      resends.addResend(sendPacket, null)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun propertyChange(event: PropertyChangeEvent) {
    if (!PropertyChangeEventType.RESENDER_PACKETS.matches(event)) return
    mainPanel.remove(resendsTabs)
    resendsTabs = ResendsCloseButtonTabbedPane()
    mainPanel.add(resendsTabs)
    resendsIndexes.clear()
    loadResenderPackets()
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
          resendsTabs.addTab(resendsIndex.toString(), resends.getComponent())
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

  private inner class ResendsCloseButtonTabbedPane : CloseButtonTabbedPane() {
    override fun removeTabAt(index: Int) {
      super.removeTabAt(index)
      try {
        var resendsIndex = resendsIndexes.removeAt(index)
        main.modelServices.resenderPackets.deleteResends(resendsIndex)
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
        background = Color.WHITE
        add(sendPanel.createPanel())
        add(recvPanel.createPanel())
        alignmentX = Component.CENTER_ALIGNMENT
        resizeWeight = 0.5
      }
    private val resendButton =
      JButton(i18nString("send")).apply {
        addActionListener {
          try {
            var sendPacket = sendPanel.getOneShotPacket() ?: return@addActionListener
            var resendController = main.coreServices.resendController
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
                }
              }
            )
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    private val resendMultipleButton =
      JButton(i18nString("send x 20")).apply {
        addActionListener {
          try {
            var sendPacket = sendPanel.getOneShotPacket() ?: return@addActionListener
            main.coreServices.resendController.resend(sendPacket, 20)
            clearLog()
            showLog(i18nString("Check the result in the History window!"))
            rollback()
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    private val attackButton =
      JButton(i18nString("send x 20 (single-packet attack)")).apply {
        addActionListener {
          try {
            var sendPacket = sendPanel.getOneShotPacket() ?: return@addActionListener
            SinglePacketAttackController(
                sendPacket,
                main.coreServices.duplexFactory,
                main.coreServices.encoderManager,
              )
              .attack(20)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
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
            maximumSize = Dimension(Short.MAX_VALUE.toInt(), 10)
          }
        )
      }

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
      var enabled = selectedIndex != 2
      resendButton.isEnabled = enabled
      resendMultipleButton.isEnabled = enabled
      attackButton.isEnabled = enabled
    }
  }
}
