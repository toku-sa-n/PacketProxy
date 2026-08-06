package packetproxy.gui

import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.event.ItemEvent
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
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JRadioButton
import javax.swing.JTextField
import javax.swing.border.LineBorder
import javax.swing.border.TitledBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.text.AbstractDocument
import javax.swing.text.AttributeSet
import javax.swing.text.DocumentFilter
import packetproxy.DNSSpoofingIPGetter
import packetproxy.PrivateDNS
import packetproxy.common.FontManager
import packetproxy.common.i18nString
import packetproxy.model.ConfigBoolean
import packetproxy.model.Configs
import packetproxy.model.PropertyChangeEventType.CONFIGS
import packetproxy.util.errWithStackTrace

class GUIOptionPrivateDNS(
  private val privateDns: PrivateDNS,
  private val configs: Configs,
  private val fontManager: FontManager,
) : PropertyChangeListener, packetproxy.DnsSpoofingConfig {
  companion object {
    private const val MAX_PORT_DIGITS = 5
  }

  private val checkBox = createCheckBox()
  private val spoofIpv4CheckBox = createSpoofIpv4CheckBox()
  private val spoofIpv6CheckBox = createSpoofIpv6CheckBox()
  private val ipv4 = createAddressField()
  private val ipv6 = createAddress6Field()
  private lateinit var auto: JRadioButton
  private lateinit var manual: JRadioButton
  private lateinit var interfaces: JComboBox<String>
  private lateinit var port: JTextField
  private lateinit var setPort: JButton
  private lateinit var portErrorLabel: JLabel
  private var portFieldDefaultBackgroundColor: Color? = null
  private var portFieldDocumentListener: DocumentListener? = null
  private val panel = createPanel()

  init {
    configs.addPropertyChangeListener(this)
    updateState()
  }

  fun dispose() {
    configs.removePropertyChangeListener(this)
  }

  fun getPanel() = panel

  override fun isAutoSpoofing() = auto.isSelected

  override fun getSpoofingIP() = if (auto.isSelected) localIp() else ipv4.text

  override fun getSpoofingIP6() = if (auto.isSelected) "" else ipv6.text

  override fun getBindInterface() = interfaces.selectedItem.toString()

  fun updateState() {
    try {
      checkBox.isSelected = ConfigBoolean(configs, "PrivateDNS").getState()
      spoofIpv4CheckBox.isSelected =
        ConfigBoolean(configs, "PrivateDNSSpoofIPv4", "true").getState()
      spoofIpv6CheckBox.isSelected =
        ConfigBoolean(configs, "PrivateDNSSpoofIPv6", "true").getState()
      updatePortFieldText(privateDns.getConfiguredPort().toString())
      if (!checkBox.isSelected) return
      if (!privateDns.start(DNSSpoofingIPGetter(this))) {
        checkBox.isSelected = false
        showError()
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    } finally {
      updatePortSetButtonEnabled()
    }
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (CONFIGS.matches(evt)) updateState()
  }

  private fun createPanel(): JPanel {
    auto =
      JRadioButton(
        i18nString("Auto (Replace resolved IP with local IP of suitable NIC automatically)"),
        true,
      )
    auto.minimumSize = Dimension(Short.MAX_VALUE.toInt(), auto.maximumSize.height)
    auto.addActionListener { updateManual() }
    manual = JRadioButton(i18nString("Manual"), false)
    manual.addActionListener { updateManual() }

    val rewriteGroup = ButtonGroup()
    rewriteGroup.add(auto)
    rewriteGroup.add(manual)

    val manualPanel = JPanel()
    manualPanel.background = ThemeColors.panelBackground()
    manualPanel.layout = BoxLayout(manualPanel, BoxLayout.X_AXIS)
    manualPanel.add(manual)
    manualPanel.add(ipv4)
    manualPanel.add(ipv6)

    val rewriteRuleBorder = TitledBorder(i18nString("Rewrite Rule"))
    rewriteRuleBorder.border = LineBorder(ThemeColors.borderColor(), 1)
    rewriteRuleBorder.titleFont = fontManager.getUIFont()
    rewriteRuleBorder.titleJustification = TitledBorder.LEFT
    rewriteRuleBorder.titlePosition = TitledBorder.TOP

    val rewriteRule = JPanel()
    rewriteRule.layout = BoxLayout(rewriteRule, BoxLayout.Y_AXIS)
    rewriteRule.background = ThemeColors.panelBackground()
    rewriteRule.border = rewriteRuleBorder
    rewriteRule.add(spoofIpv4CheckBox)
    rewriteRule.add(spoofIpv6CheckBox)
    rewriteRule.add(auto)
    rewriteRule.add(manualPanel)
    rewriteRule.maximumSize =
      Dimension(rewriteRule.preferredSize.width, rewriteRule.minimumSize.height)

    return JPanel().apply {
      background = ThemeColors.panelBackground()
      layout = BoxLayout(this, BoxLayout.Y_AXIS)
      add(checkBox)
      add(createInterfaceSetting())
      add(createPortSetting())
      add(rewriteRule)
      alignmentX = Component.LEFT_ALIGNMENT
    }
  }

  private fun createSpoofIpv4CheckBox(): JCheckBox {
    val box = JCheckBox(i18nString("Spoofing A Record"))
    box.isSelected = true
    box.addActionListener {
      ConfigBoolean(configs, "PrivateDNSSpoofIPv4", "true").setState(box.isSelected)
    }
    box.minimumSize = Dimension(Short.MAX_VALUE.toInt(), box.maximumSize.height)
    return box
  }

  private fun createSpoofIpv6CheckBox(): JCheckBox {
    val box = JCheckBox(i18nString("Spoofing AAAA Record"))
    box.isSelected = true
    box.addActionListener {
      ConfigBoolean(configs, "PrivateDNSSpoofIPv6", "true").setState(box.isSelected)
    }
    box.minimumSize = Dimension(Short.MAX_VALUE.toInt(), box.maximumSize.height)
    return box
  }

  private fun createCheckBox(): JCheckBox {
    val box = JCheckBox(i18nString("Use private DNS server"))
    box.addActionListener {
      if (!box.isSelected) {
        privateDns.stop()
        return@addActionListener
      }
      if (!privateDns.start(DNSSpoofingIPGetter(this))) {
        box.isSelected = false
        showError()
      }
    }
    box.minimumSize = Dimension(Short.MAX_VALUE.toInt(), box.maximumSize.height)
    return box
  }

  private fun createAddressField(): JTextField {
    val text = JTextField(localIp())
    text.maximumSize = Dimension(300, 30)
    text.preferredSize = Dimension(200, 30)
    text.isEnabled = false
    return text
  }

  private fun createAddress6Field(): JTextField {
    val text = JTextField(localIp6())
    text.maximumSize = Dimension(600, 30)
    text.preferredSize = Dimension(500, 30)
    text.isEnabled = false
    return text
  }

  private fun createInterfaceSetting(): JComponent {
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
    interfaces.maximumRowCount = interfaces.itemCount
    interfaces.selectedItem = "0.0.0.0"
    interfaces.addItemListener { event ->
      if (event.stateChange != ItemEvent.SELECTED || event.item == null) return@addItemListener
      restartForBindingInterfaceChange()
    }
    interfaces.maximumSize = Dimension(interfaces.minimumSize.width, interfaces.minimumSize.height)

    return JPanel().apply {
      background = ThemeColors.panelBackground()
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(interfaces)
      add(JLabel(i18nString("will be used for Binding Interface")))
      maximumSize = Dimension(Short.MAX_VALUE.toInt(), maximumSize.height)
    }
  }

  private fun createPortSetting(): JComponent {
    val portLabel = JLabel(i18nString("Port"))
    return JPanel().apply {
      background = ThemeColors.panelBackground()
      layout = BoxLayout(this, BoxLayout.Y_AXIS)
      add(createPortSettingRow(portLabel))
      add(createPortSettingMessageRow(portLabel))
      maximumSize = Dimension(Short.MAX_VALUE.toInt(), maximumSize.height)
      updatePortSetButtonEnabled()
    }
  }

  private fun createPortSettingRow(portLabel: JLabel): JPanel {
    port = createDnsPortField()
    setPort = createDnsPortSetButton()
    return JPanel().apply {
      background = ThemeColors.panelBackground()
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(portLabel)
      add(Box.createHorizontalStrut(4))
      add(port)
      add(setPort)
      add(JLabel(i18nString("will be used for Binding Port")))
      maximumSize = Dimension(Short.MAX_VALUE.toInt(), maximumSize.height)
    }
  }

  private fun createPortSettingMessageRow(portLabel: JLabel): JPanel {
    portErrorLabel = JLabel(" ")
    portErrorLabel.foreground = ThemeColors.errorForeground()
    return JPanel().apply {
      background = ThemeColors.panelBackground()
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(Box.createRigidArea(Dimension(portLabel.preferredSize.width, 0)))
      add(Box.createHorizontalStrut(4))
      add(portErrorLabel)
      maximumSize = Dimension(Short.MAX_VALUE.toInt(), maximumSize.height)
    }
  }

  private fun createDnsPortField(): JTextField {
    val field = JTextField(privateDns.getConfiguredPort().toString())
    field.maximumSize = Dimension(100, field.minimumSize.height)
    portFieldDefaultBackgroundColor = field.background
    installDnsPortFieldDocumentFilter(field)
    installDnsPortFieldDocumentListener(field)
    return field
  }

  private fun installDnsPortFieldDocumentFilter(field: JTextField) {
    (field.document as AbstractDocument).documentFilter =
      object : DocumentFilter() {
        override fun insertString(
          fb: FilterBypass,
          offset: Int,
          string: String?,
          attr: AttributeSet?,
        ) {
          if (string == null) return
          val nextLength = fb.document.length + string.length
          if (isDigitsOnly(string) && nextLength <= MAX_PORT_DIGITS) {
            super.insertString(fb, offset, string, attr)
          }
        }

        override fun replace(
          fb: FilterBypass,
          offset: Int,
          length: Int,
          text: String?,
          attrs: AttributeSet?,
        ) {
          if (text == null) {
            super.replace(fb, offset, length, text, attrs)
            return
          }
          val nextLength = fb.document.length - length + text.length
          if (isDigitsOnly(text) && nextLength <= MAX_PORT_DIGITS) {
            super.replace(fb, offset, length, text, attrs)
          }
        }
      }
  }

  private fun installDnsPortFieldDocumentListener(field: JTextField) {
    portFieldDocumentListener =
      object : DocumentListener {
        override fun insertUpdate(e: DocumentEvent) = updatePortSetButtonEnabled()

        override fun removeUpdate(e: DocumentEvent) = updatePortSetButtonEnabled()

        override fun changedUpdate(e: DocumentEvent) = updatePortSetButtonEnabled()
      }
    field.document.addDocumentListener(portFieldDocumentListener)
  }

  private fun createDnsPortSetButton(): JButton {
    val button = JButton(i18nString("Set"))
    button.addActionListener {
      val portValue = parsePortText(port.text) ?: return@addActionListener
      privateDns.setPort(portValue, DNSSpoofingIPGetter(this))
    }
    return button
  }

  private fun isDigitsOnly(text: String): Boolean = text.all { it in '0'..'9' }

  private fun updateManual() {
    ipv4.isEnabled = manual.isSelected
    ipv6.isEnabled = manual.isSelected
  }

  private fun updatePortSetButtonEnabled() {
    if (!::setPort.isInitialized || !::port.isInitialized) return
    val portValue = parsePortText(port.text)
    if (portValue == null) {
      setPort.isEnabled = false
      clearPortError()
      return
    }
    if (!privateDns.isPortInRange(portValue)) {
      setPort.isEnabled = false
      setPortError(i18nString("Port number must be between 1 and 65535"))
      return
    }
    clearPortError()
    setPort.isEnabled = privateDns.isPortChangeNeeded(portValue)
  }

  private fun setPortError(message: String) {
    if (::portErrorLabel.isInitialized) portErrorLabel.text = message
    if (::port.isInitialized) {
      port.isOpaque = true
      port.background = ThemeColors.errorBackground()
    }
  }

  private fun clearPortError() {
    if (::portErrorLabel.isInitialized) portErrorLabel.text = " "
    if (::port.isInitialized) {
      portFieldDefaultBackgroundColor?.let { port.background = it }
    }
  }

  private fun parsePortText(portText: String): Int? =
    try {
      portText.trim().toInt()
    } catch (_: Exception) {
      null
    }

  private fun updatePortFieldText(text: String) {
    if (!::port.isInitialized) return
    portFieldDocumentListener?.let { port.document.removeDocumentListener(it) }
    try {
      port.text = text
    } catch (e: Exception) {
      errWithStackTrace(e)
    } finally {
      portFieldDocumentListener?.let { port.document.addDocumentListener(it) }
    }
  }

  private fun restartForBindingInterfaceChange() {
    try {
      if (!privateDns.isRunning()) return
      if (!privateDns.restart(DNSSpoofingIPGetter(this))) {
        checkBox.isSelected = false
        showError()
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
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
      i18nString("Failed to start private DNS server. Please check permissions and listen port."),
      i18nString("Error"),
      JOptionPane.ERROR_MESSAGE,
    )
  }
}
