package packetproxy.gui

import java.awt.Color
import java.awt.Dimension
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.security.SecureRandom
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import packetproxy.common.*
import packetproxy.model.ConfigBoolean
import packetproxy.model.ConfigString
import packetproxy.model.PropertyChangeEventType.CONFIGS
import packetproxy.util.errWithStackTrace

class GUIOptionHubServer(private val frame: GUIMain) : PropertyChangeListener {
  private val panel = JPanel()
  private lateinit var checkBox: JCheckBox
  private lateinit var token: JTextField
  private lateinit var regenerate: JButton
  private var server: ConfigHttpServer? = null
  private val secureRandom = SecureRandom()

  init {
    panel.background = Color.WHITE
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(createCheckBox())
    panel.add(createTokenPanel())
    frame.modelServices.configs.addPropertyChangeListener(this)
  }

  fun dispose() {
    frame.modelServices.configs.removePropertyChangeListener(this)
  }

  fun createPanel(): JComponent {
    if (
      ConfigString(frame.modelServices.configs, "SharingConfigsAccessToken").getString().isEmpty()
    ) {
      generateAccessToken()
    }
    refresh()
    return panel
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (CONFIGS.matches(evt)) refresh()
  }

  private fun createCheckBox(): JCheckBox {
    checkBox = JCheckBox(i18nString("Enabled"))
    checkBox.addActionListener {
      try {
        ConfigBoolean(frame.modelServices.configs, "SharingConfigs").setState(checkBox.isSelected)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    checkBox.minimumSize = Dimension(Short.MAX_VALUE.toInt(), checkBox.maximumSize.height)
    return checkBox
  }

  private fun createTokenPanel(): JComponent {
    val row = JPanel()
    row.background = Color.WHITE
    row.layout = BoxLayout(row, BoxLayout.X_AXIS)
    row.add(JLabel(i18nString("AccessToken:")))
    token = JTextField()
    token.isEditable = false
    token.maximumSize = Dimension(Short.MAX_VALUE.toInt(), token.minimumSize.height)
    row.add(token)
    regenerate = JButton(i18nString("Regenerate"))
    regenerate.addActionListener {
      try {
        generateAccessToken()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    row.add(regenerate)
    return row
  }

  private fun refresh() {
    try {
      token.text =
        ConfigString(frame.modelServices.configs, "SharingConfigsAccessToken").getString()
      checkBox.isSelected = ConfigBoolean(frame.modelServices.configs, "SharingConfigs").getState()
      if (checkBox.isSelected) {
        token.isEnabled = true
        regenerate.isEnabled = true
        if (server?.isAlive != true) {
          server = ConfigHttpServer("localhost", 32349, frame, token.text)
          server!!.start()
        }
      } else {
        server?.stop()
        server = null
        token.isEnabled = false
        regenerate.isEnabled = false
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun generateAccessToken() {
    val bytes = ByteArray(20)
    secureRandom.nextBytes(bytes)
    val tokenValue = bytes.joinToString("") { b -> "%02x".format(b) }.take(20)
    ConfigString(frame.modelServices.configs, "SharingConfigsAccessToken").setString(tokenValue)
  }
}
