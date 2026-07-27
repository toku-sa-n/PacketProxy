package packetproxy.gui

import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.ButtonGroup
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JRadioButton
import javax.swing.JTextField
import packetproxy.DNSSpoofingIPGetter
import packetproxy.PrivateDNS
import packetproxy.common.I18nString
import packetproxy.model.ConfigBoolean
import packetproxy.model.Configs
import packetproxy.model.PropertyChangeEventType.CONFIGS
import packetproxy.util.Logging.errWithStackTrace

class GUIOptionPrivateDNS : PropertyChangeListener {
  private val privateDns = PrivateDNS.getInstance()
  private val checkBox = JCheckBox(I18nString.get("Use private DNS server"))
  private val ipv4 = JTextField()
  private val ipv6 = JTextField()
  private val auto =
    JRadioButton(
      I18nString.get("Auto (Replace resolved IP with local IP of suitable NIC automatically)"),
      true,
    )
  private val manual = JRadioButton(I18nString.get("Manual"))
  private lateinit var interfaces: JComboBox<String>
  private lateinit var port: JTextField
  private lateinit var setPort: JButton
  private val panel = JPanel()

  init {
    ipv4.text = localIp()
    ipv6.text = localIp6()
    ipv4.isEnabled = false
    ipv6.isEnabled = false
    panel.background = Color.WHITE
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    checkBox.addActionListener {
      if (!checkBox.isSelected) privateDns.stop()
      else if (!privateDns.start(DNSSpoofingIPGetter(this))) {
        checkBox.isSelected = false
        showError()
      }
    }
    panel.add(checkBox)
    panel.add(interfacePanel())
    panel.add(portPanel())
    val group = ButtonGroup()
    group.add(auto)
    group.add(manual)
    auto.addActionListener { updateManual() }
    manual.addActionListener { updateManual() }
    val manualRow = JPanel()
    manualRow.background = Color.WHITE
    manualRow.layout = BoxLayout(manualRow, BoxLayout.X_AXIS)
    manualRow.add(manual)
    manualRow.add(ipv4)
    manualRow.add(ipv6)
    panel.add(auto)
    panel.add(manualRow)
    panel.alignmentX = Component.LEFT_ALIGNMENT
    Configs.getInstance().addPropertyChangeListener(this)
    updateState()
  }

  fun getPanel() = panel

  fun isAutoSpoofing() = auto.isSelected

  fun getSpoofingIP() = if (auto.isSelected) localIp() else ipv4.text

  fun getSpoofingIP6() = if (auto.isSelected) "" else ipv6.text

  fun getBindInterface() = interfaces.selectedItem.toString()

  fun updateState() {
    try {
      checkBox.isSelected = ConfigBoolean("PrivateDNS").getState()
      port.text = privateDns.getConfiguredPort().toString()
      if (checkBox.isSelected && !privateDns.start(DNSSpoofingIPGetter(this))) {
        checkBox.isSelected = false
        showError()
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (CONFIGS.matches(evt)) updateState()
  }

  private fun interfacePanel(): JPanel {
    val addresses = mutableListOf("0.0.0.0")
    try {
      NetworkInterface.getNetworkInterfaces()
        .toList()
        .flatMap { it.interfaceAddresses }
        .map { it.address }
        .filterIsInstance<Inet4Address>()
        .forEach { addresses.add(it.hostAddress) }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    interfaces = JComboBox(addresses.toTypedArray())
    interfaces.selectedItem = "0.0.0.0"
    interfaces.addItemListener {
      if (
        it.stateChange == java.awt.event.ItemEvent.SELECTED &&
          privateDns.isRunning() &&
          !privateDns.restart(DNSSpoofingIPGetter(this))
      ) {
        checkBox.isSelected = false
        showError()
      }
    }
    return JPanel().apply {
      background = Color.WHITE
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(interfaces)
      add(JLabel(I18nString.get("will be used for Binding Interface")))
    }
  }

  private fun portPanel(): JPanel {
    port = JTextField(privateDns.getConfiguredPort().toString())
    port.maximumSize = Dimension(100, port.minimumSize.height)
    setPort = JButton(I18nString.get("Set"))
    setPort.addActionListener {
      port.text.toIntOrNull()?.let { privateDns.setPort(it, DNSSpoofingIPGetter(this)) }
    }
    return JPanel().apply {
      background = Color.WHITE
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(JLabel(I18nString.get("Port")))
      add(Box.createHorizontalStrut(4))
      add(port)
      add(setPort)
      add(JLabel(I18nString.get("will be used for Binding Port")))
    }
  }

  private fun updateManual() {
    ipv4.isEnabled = manual.isSelected
    ipv6.isEnabled = manual.isSelected
  }

  private fun localIp(): String =
    try {
      NetworkInterface.getNetworkInterfaces()
        .toList()
        .flatMap { it.inetAddresses.toList() }
        .filterIsInstance<Inet4Address>()
        .firstOrNull()
        ?.hostAddress ?: "127.0.0.1"
    } catch (_: Exception) {
      "127.0.0.1"
    }

  private fun localIp6(): String =
    try {
      NetworkInterface.getNetworkInterfaces()
        .toList()
        .flatMap { it.inetAddresses.toList() }
        .filterIsInstance<Inet6Address>()
        .firstOrNull()
        ?.hostAddress ?: "::1"
    } catch (_: Exception) {
      "::1"
    }

  private fun showError() {
    JOptionPane.showMessageDialog(
      panel,
      I18nString.get(
        "Failed to start private DNS server. Please check permissions and listen port."
      ),
      I18nString.get("Error"),
      JOptionPane.ERROR_MESSAGE,
    )
  }
}
