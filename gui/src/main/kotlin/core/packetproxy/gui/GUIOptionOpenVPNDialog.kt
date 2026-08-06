package packetproxy.gui

import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import packetproxy.common.*
import packetproxy.model.OpenVPNForwardPort
import packetproxy.util.errWithStackTrace

class GUIOptionOpenVPNDialog(private val owner: JFrame) : JDialog(owner) {
  private val combo = JComboBox<String>()
  private val buttonCancel = JButton(i18nString("Cancel"))
  private val buttonSet = JButton(i18nString("Save"))
  private val fromPortField = HintTextField("443")
  private val toPortField = HintTextField("8443")
  private var forwardPort: OpenVPNForwardPort? = null

  init {
    title = i18nString("Setting")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 250, rect.y + rect.height / 2 - 250, 500, 500)

    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(createProtoSetting())
    panel.add(createFromPortSetting())
    panel.add(createToPortSetting())
    panel.add(buttons())
    contentPane.add(panel)

    buttonCancel.addActionListener {
      forwardPort = null
      dispose()
    }
    buttonSet.addActionListener { save() }
  }

  fun showDialog(): OpenVPNForwardPort? {
    isModal = true
    isVisible = true
    return forwardPort
  }

  fun showDialog(preset: OpenVPNForwardPort): OpenVPNForwardPort? {
    combo.selectedItem = preset.getType()?.name
    fromPortField.text = preset.getFromPort().toString()
    toPortField.text = preset.getToPort().toString()
    isModal = true
    isVisible = true
    return forwardPort
  }

  private fun save() {
    val fromPort = parsePortOrWarn(fromPortField.text, FROM_PORT_LABEL) ?: return
    val toPort = parsePortOrWarn(toPortField.text, TO_PORT_LABEL) ?: return
    try {
      val type = OpenVPNForwardPort.TYPE.valueOf(combo.selectedItem as String)
      forwardPort = OpenVPNForwardPort(type, fromPort, toPort)
      dispose()
    } catch (e: Exception) {
      errWithStackTrace(e)
      JOptionPane.showMessageDialog(this, e.message, i18nString("Error"), JOptionPane.ERROR_MESSAGE)
    }
  }

  /** 不正なポート番号が入力された場合はダイアログで通知してnullを返す */
  private fun parsePortOrWarn(text: String, label: String): Int? {
    val port = PortValidator.parse(text)
    if (port == null) {
      JOptionPane.showMessageDialog(
        this,
        PortValidator.errorMessage(i18nString(label)),
        i18nString("Error"),
        JOptionPane.ERROR_MESSAGE,
      )
      return null
    }
    return port
  }

  private fun labelAndObject(labelName: String, obj: JComponent): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    val label = JLabel(labelName)
    label.preferredSize = Dimension(150, label.maximumSize.height)
    panel.add(label)
    obj.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
    panel.add(obj)
    return panel
  }

  private fun buttons(): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), buttonSet.maximumSize.height)
    panel.add(buttonCancel)
    panel.add(buttonSet)
    return panel
  }

  private fun createProtoSetting(): JComponent {
    combo.prototypeDisplayValue = "xxxxxxx"
    combo.addItem("TCP")
    combo.addItem("UDP")
    combo.maximumRowCount = combo.itemCount
    combo.maximumSize = Dimension(Short.MAX_VALUE.toInt(), combo.minimumSize.height)
    return labelAndObject(i18nString("protocol"), combo)
  }

  private fun createFromPortSetting(): JComponent =
    labelAndObject(i18nString(FROM_PORT_LABEL), fromPortField)

  private fun createToPortSetting(): JComponent =
    labelAndObject(i18nString(TO_PORT_LABEL), toPortField)

  companion object {
    private const val FROM_PORT_LABEL = "src port"
    private const val TO_PORT_LABEL = "dst port"
  }
}
