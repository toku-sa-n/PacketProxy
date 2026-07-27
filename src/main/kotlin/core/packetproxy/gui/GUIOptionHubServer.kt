package packetproxy.gui

import java.awt.Color
import java.awt.Dimension
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import org.apache.commons.lang3.RandomStringUtils
import packetproxy.common.ConfigHttpServer
import packetproxy.common.I18nString
import packetproxy.model.ConfigBoolean
import packetproxy.model.ConfigString
import packetproxy.model.Configs
import packetproxy.model.PropertyChangeEventType.CONFIGS
import packetproxy.util.Logging.errWithStackTrace

class GUIOptionHubServer(private val frame: JFrame) : PropertyChangeListener {
  private val panel = JPanel()
  private lateinit var checkBox: JCheckBox
  private lateinit var token: JTextField
  private lateinit var regenerate: JButton
  private var server: ConfigHttpServer? = null

  init {
    panel.background = Color.WHITE
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(createCheckBox())
    panel.add(createTokenPanel())
    Configs.getInstance().addPropertyChangeListener(this)
  }

  fun createPanel(): JComponent {
    if (ConfigString("SharingConfigsAccessToken").getString().isEmpty()) generateAccessToken()
    refresh()
    return panel
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (CONFIGS.matches(evt)) refresh()
  }

  private fun createCheckBox(): JCheckBox {
    checkBox = JCheckBox(I18nString.get("Enabled"))
    checkBox.addActionListener {
      try {
        ConfigBoolean("SharingConfigs").setState(checkBox.isSelected)
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
    row.add(JLabel("AccessToken:"))
    token = JTextField()
    token.isEditable = false
    token.maximumSize = Dimension(Short.MAX_VALUE.toInt(), token.minimumSize.height)
    row.add(token)
    regenerate = JButton(I18nString.get("Regenerate"))
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
      token.text = ConfigString("SharingConfigsAccessToken").getString()
      checkBox.isSelected = ConfigBoolean("SharingConfigs").getState()
      if (checkBox.isSelected) {
        token.isEnabled = true
        regenerate.isEnabled = true
        if (server?.isAlive != true) {
          server = ConfigHttpServer("localhost", 32349, token.text)
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
    ConfigString("SharingConfigsAccessToken").setString(RandomStringUtils.randomAlphabetic(20))
  }
}
