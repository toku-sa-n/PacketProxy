package packetproxy.gui

import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import packetproxy.common.PortValidator
import packetproxy.common.i18nString
import packetproxy.model.SSLPassThrough
import packetproxy.util.errWithStackTrace

class GUIOptionSSLPassThroughDialog(owner: JFrame) : JDialog(owner) {
  private val serverName = HintTextField(".*\\.apple\\.com")
  private val listenPort = HintTextField(i18nString("Use * to apply all ports"))
  private val cancel = JButton(i18nString("Cancel"))
  private val save = JButton(i18nString("Save"))
  private var result: SSLPassThrough? = null

  init {
    title = i18nString("Setting")
    var rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 250, rect.y + rect.height / 2 - 250, 500, 500)
    var panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(labeled(i18nString("Target server name:"), serverName))
    panel.add(labeled(i18nString(PORT_LABEL), listenPort))
    var footer = JPanel()
    footer.layout = BoxLayout(footer, BoxLayout.X_AXIS)
    footer.maximumSize = Dimension(Short.MAX_VALUE.toInt(), save.maximumSize.height)
    footer.add(cancel)
    footer.add(save)
    panel.add(footer)
    contentPane.add(panel)
    cancel.addActionListener {
      result = null
      dispose()
    }
    save.addActionListener { saveSetting() }
  }

  fun showDialog(preset: SSLPassThrough): SSLPassThrough? {
    serverName.text = preset.getServerName()
    var port = preset.getListenPort()
    listenPort.text = if (port == SSLPassThrough.ALL_PORTS) "*" else port.toString()
    isModal = true
    isVisible = true
    return result
  }

  fun showDialog(): SSLPassThrough? {
    isModal = true
    isVisible = true
    return result
  }

  private fun saveSetting() {
    var port = parseListenPort()
    if (port == null) {
      JOptionPane.showMessageDialog(
        this,
        PortValidator.errorMessage(i18nString(PORT_LABEL)),
        i18nString("Error"),
        JOptionPane.ERROR_MESSAGE,
      )
      return
    }
    try {
      result = SSLPassThrough(serverName.text, port)
      dispose()
    } catch (e: Exception) {
      errWithStackTrace(e)
      JOptionPane.showMessageDialog(this, e.message, i18nString("Error"), JOptionPane.ERROR_MESSAGE)
    }
  }

  /** 全ポートを表す "*" も受け付ける。不正な入力の場合はnullを返す */
  private fun parseListenPort(): Int? {
    var portText = listenPort.text.trim()
    if (portText == "*") {
      return SSLPassThrough.ALL_PORTS
    }
    return PortValidator.parse(portText)
  }

  private fun labeled(text: String, component: JComponent): JComponent {
    var panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    var label = JLabel(text)
    label.preferredSize = Dimension(150, label.maximumSize.height)
    panel.add(label)
    component.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
    panel.add(component)
    return panel
  }

  companion object {
    private const val PORT_LABEL = "Target listen port:"
  }
}
