package packetproxy.gui

import java.awt.Component
import java.awt.Dimension
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.net.Inet4Address
import java.net.NetworkInterface
import javax.swing.BoxLayout
import javax.swing.ButtonGroup
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JRadioButton
import javax.swing.JTextField
import javax.swing.border.LineBorder
import javax.swing.border.TitledBorder
import packetproxy.common.*
import packetproxy.model.ConfigBoolean
import packetproxy.model.OpenVPNForwardPort
import packetproxy.util.errWithStackTrace

class GUIOptionOpenVPN(owner: GUIMain) : GUIOptionComponentBase<OpenVPNForwardPort>(owner) {
  private val forwardPorts = owner.modelServices.openVPNForwardPorts
  private val tableList = mutableListOf<OpenVPNForwardPort>()
  private val openVPN = owner.coreServices.openVPN
  private val checkBox = createCheckBox()
  private val vpnProtocol = JComboBox<String>()
  private val textField = createAddressField()
  private val auto =
    JRadioButton(
      i18nString("Auto (Replace resolved IP with local IP of suitable NIC automatically)"),
      true,
    )
  private val manual = JRadioButton(i18nString("Manual"), false)
  private val base: JPanel

  init {
    forwardPorts.addPropertyChangeListener(this)
    jcomponent =
      createComponent(
        i18nStringArray("Proto", "src port", "dst port"),
        intArrayOf(80, 80, 80),
        object : MouseAdapter() {
          override fun mouseClicked(e: MouseEvent) {
            try {
              val rowIndex = table.rowAtPoint(e.point)
              if (rowIndex >= 0) {
                table.setRowSelectionInterval(rowIndex, rowIndex)
              }
            } catch (ex: Exception) {
              errWithStackTrace(ex)
            }
          }
        },
        {
          try {
            GUIOptionOpenVPNDialog(owner).showDialog()?.let(forwardPorts::create)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            val old = getSelectedTableContent() ?: return@createComponent
            GUIOptionOpenVPNDialog(owner).showDialog(old)?.let {
              forwardPorts.delete(old)
              forwardPorts.create(it)
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            getSelectedTableContent()?.let { forwardPorts.delete(it) }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
      )
    updateImpl()
    base = buildPanel()
    updateState()
  }

  fun dispose() {
    forwardPorts.removePropertyChangeListener(this)
  }

  fun getPanel() = base

  fun isAutoSpoofing() = auto.isSelected

  fun getSpoofingIP(): String {
    if (auto.isSelected) {
      try {
        return getLocalIP()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    } else {
      return textField.text
    }
    return ""
  }

  fun updateState() {
    try {
      checkBox.isSelected = ConfigBoolean(owner.modelServices.configs, "OpenVPN").getState()
      if (checkBox.isSelected) {
        startOpenVpnOffEdt()
      }
    } catch (e: Exception) {
      checkBox.isSelected = false
      errWithStackTrace(e)
    }
  }

  override fun addTableContent(value: OpenVPNForwardPort) {
    tableList.add(value)
    option_model.addRow(arrayOf<Any?>(value.getType(), value.getFromPort(), value.getToPort()))
  }

  override fun updateTable(values: List<OpenVPNForwardPort>) {
    clearTableContents()
    values.forEach(::addTableContent)
  }

  override fun updateImpl() {
    try {
      updateTable(forwardPorts.queryAll())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    tableList.clear()
  }

  override fun getSelectedTableContent(): OpenVPNForwardPort? {
    val rowIndex = selectedModelRowOrNull() ?: return null
    return getTableContent(rowIndex)
  }

  override fun getTableContent(rowIndex: Int) = tableList[rowIndex]

  private fun buildPanel(): JPanel {
    auto.minimumSize = Dimension(Short.MAX_VALUE.toInt(), auto.maximumSize.height)
    auto.addActionListener { textField.isEnabled = manual.isSelected }
    manual.addActionListener { textField.isEnabled = manual.isSelected }

    val rewriteGroup = ButtonGroup()
    rewriteGroup.add(auto)
    rewriteGroup.add(manual)

    val manualPanel = JPanel()
    manualPanel.background = ThemeColors.panelBackground()
    manualPanel.layout = BoxLayout(manualPanel, BoxLayout.X_AXIS)
    manualPanel.add(manual)
    manualPanel.add(textField)

    val rewriteRuleBorder = TitledBorder(i18nString("Rewrite Rule"))
    rewriteRuleBorder.border = LineBorder(ThemeColors.borderColor(), 1)
    rewriteRuleBorder.titleFont = owner.modelServices.fontManager.getUIFont()
    rewriteRuleBorder.titleJustification = TitledBorder.LEFT
    rewriteRuleBorder.titlePosition = TitledBorder.TOP

    val rewriteRule = JPanel()
    rewriteRule.layout = BoxLayout(rewriteRule, BoxLayout.Y_AXIS)
    rewriteRule.background = ThemeColors.panelBackground()
    rewriteRule.border = rewriteRuleBorder
    rewriteRule.add(auto)
    rewriteRule.add(manualPanel)
    rewriteRule.maximumSize =
      Dimension(rewriteRule.preferredSize.width, rewriteRule.minimumSize.height)

    val panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(checkBox)
    panel.add(createProtoSetting())
    panel.add(rewriteRule)
    panel.add(createPanel())
    panel.alignmentX = Component.LEFT_ALIGNMENT
    return panel
  }

  private fun createCheckBox(): JCheckBox {
    val box = JCheckBox(i18nString("Use OpenVPN"))
    box.addActionListener {
      try {
        if (box.isSelected) {
          startOpenVpnOffEdt()
        } else {
          openVPN.stopServer()
          ConfigBoolean(owner.modelServices.configs, "OpenVPN").setState(false)
        }
      } catch (e: Exception) {
        box.isSelected = false
        try {
          ConfigBoolean(owner.modelServices.configs, "OpenVPN").setState(false)
        } catch (ex: Exception) {
          errWithStackTrace(ex)
        }
        errWithStackTrace(e)
      }
    }
    box.minimumSize = Dimension(Short.MAX_VALUE.toInt(), box.maximumSize.height)
    return box
  }

  private fun startOpenVpnOffEdt() {
    val proto = vpnProtocol.selectedItem.toString()
    val spoofIp = getSpoofingIP()
    object : javax.swing.SwingWorker<Boolean, Void>() {
        override fun doInBackground(): Boolean = openVPN.startServer(spoofIp, proto)

        override fun done() {
          try {
            val started = get()
            checkBox.isSelected = started
            ConfigBoolean(owner.modelServices.configs, "OpenVPN").setState(started)
          } catch (e: Exception) {
            checkBox.isSelected = false
            try {
              ConfigBoolean(owner.modelServices.configs, "OpenVPN").setState(false)
            } catch (ex: Exception) {
              errWithStackTrace(ex)
            }
            errWithStackTrace(e)
          }
        }
      }
      .execute()
  }

  private fun createProtoSetting(): JComponent {
    val panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)

    vpnProtocol.prototypeDisplayValue = "xxxxxxx"
    vpnProtocol.addItem("TCP")
    vpnProtocol.addItem("UDP")
    vpnProtocol.maximumRowCount = vpnProtocol.itemCount
    vpnProtocol.selectedItem = "UDP"
    vpnProtocol.maximumSize =
      Dimension(vpnProtocol.minimumSize.width, vpnProtocol.minimumSize.height)
    panel.add(vpnProtocol)
    panel.add(JLabel(i18nString("will be used for VPN")))
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), panel.maximumSize.height)
    return panel
  }

  private fun createAddressField(): JTextField {
    val text = JTextField("")
    try {
      text.text = getLocalIP()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    text.maximumSize = Dimension(300, 30)
    text.isEnabled = false
    return text
  }

  private fun getLocalIP(): String {
    val ips =
      NetworkInterface.getNetworkInterfaces()
        .toList()
        .flatMap { it.inetAddresses.toList() }
        .filterIsInstance<Inet4Address>()
        .map { it.hostAddress }

    var pubIp: String? = null
    var corpIp: String? = null
    for (ip in ips) {
      if (ip.startsWith("172.23")) corpIp = ip
      if (ip.startsWith("172.25")) pubIp = ip
    }
    if (pubIp != null) return pubIp
    if (corpIp != null) return corpIp
    return ips.firstOrNull { it != "127.0.0.1" } ?: "127.0.0.1"
  }
}
