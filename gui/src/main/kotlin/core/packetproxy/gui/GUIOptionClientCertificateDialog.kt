package packetproxy.gui

import java.awt.Dimension
import java.awt.event.ItemEvent
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JTextField
import packetproxy.common.i18nString
import packetproxy.model.ClientCertificate
import packetproxy.util.errWithStackTrace

class GUIOptionClientCertificateDialog(private val owner: GUIMain) : JDialog(owner) {
  private val certificateTypeCombo = JComboBox<String>()
  private val certificatePathField = JTextField()
  private val storePasswordField = JPasswordField()
  private val keyPasswordField = JPasswordField()
  private val serverCombo = JComboBox<String>()
  private var certFileChooser = NativeFileChooser()
  private var certificate: ClientCertificate? = null

  init {
    title = i18nString("Setting")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 400, rect.y + rect.height / 2 - 250, 800, 500)
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(createCertificateTypeSetting())
    panel.add(createCertificatePathSetting())
    panel.add(labeled(i18nString("Password of the certifacate file:"), storePasswordField))
    panel.add(labeled(i18nString("Password of the secret key:"), keyPasswordField))
    panel.add(createAppliedServers())
    val buttons = JPanel()
    buttons.layout = BoxLayout(buttons, BoxLayout.X_AXIS)
    val cancelButton = JButton(i18nString("Cancel"))
    val saveButton = JButton(i18nString("Save"))
    buttons.maximumSize = Dimension(Short.MAX_VALUE.toInt(), saveButton.maximumSize.height)
    buttons.add(cancelButton)
    buttons.add(saveButton)
    panel.add(buttons)
    contentPane.add(panel)
    cancelButton.addActionListener {
      certificate = null
      dispose()
    }
    saveButton.addActionListener { save() }
  }

  @Throws(Exception::class)
  fun showDialog(): ClientCertificate? {
    if (owner.modelServices.servers.queryAll().isEmpty()) {
      JOptionPane.showMessageDialog(
        owner,
        i18nString("Set server you wish to connect into 'Servers setting' first."),
        i18nString("Message"),
        JOptionPane.INFORMATION_MESSAGE,
      )
      certificate = null
      return null
    }
    isModal = true
    isVisible = true
    return certificate
  }

  @Throws(Exception::class)
  fun showDialog(preset: ClientCertificate): ClientCertificate? {
    certificateTypeCombo.selectedItem = preset.getType()?.getText()
    certificatePathField.text = preset.getPath()
    storePasswordField.text = preset.getStorePassword()
    keyPasswordField.text = preset.getKeyPassword()
    serverCombo.selectedItem = preset.getServerName(owner.modelServices.database)
    isModal = true
    isVisible = true
    return certificate
  }

  private fun save() {
    try {
      val type =
        ClientCertificate.Type.getTypeFromText(certificateTypeCombo.selectedItem.toString())
          ?: return
      val serverName = serverCombo.selectedItem as? String ?: return
      val server = owner.modelServices.servers.queryByString(serverName) ?: return
      val converted =
        try {
          ClientCertificate.convert(
            type,
            server,
            certificatePathField.text,
            storePasswordField.password,
            keyPasswordField.password,
          )
        } catch (_: Exception) {
          certificate = null
          JOptionPane.showMessageDialog(
            owner,
            i18nString("[Error] incorrect certificate file password."),
            i18nString("Message"),
            JOptionPane.INFORMATION_MESSAGE,
          )
          return
        }
      certificate = converted
      if (!owner.modelServices.clientCertificates.hasCorrectSecretKey(converted)) {
        certificate = null
        JOptionPane.showMessageDialog(
          owner,
          i18nString("[Error] incorrect secret key password."),
          i18nString("Message"),
          JOptionPane.INFORMATION_MESSAGE,
        )
        return
      }
      dispose()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun createCertificateTypeSetting(): JComponent {
    ClientCertificate.Type.values().forEach { certificateTypeCombo.addItem(it.getText()) }
    certificateTypeCombo.selectedIndex = 0 /* default p12 */
    certificateTypeCombo.maximumRowCount = ClientCertificate.Type.values().size
    certificateTypeCombo.addItemListener { event ->
      if (event.stateChange != ItemEvent.SELECTED) return@addItemListener
      certFileChooser = NativeFileChooser()
      certFileChooser.setAcceptAllFileFilterUsed(false)
      when (ClientCertificate.Type.getTypeFromText(event.item as String)) {
        ClientCertificate.Type.JKS ->
          certFileChooser.addChoosableFileFilter(
            i18nString("Client Certificate file (*.jks)"),
            "jks",
          )
        ClientCertificate.Type.P12 ->
          certFileChooser.addChoosableFileFilter(
            i18nString("Client Certificate file (*.p12, *.pfx)"),
            "p12",
            "pfx",
          )
        else -> {}
      }
    }
    certFileChooser.addChoosableFileFilter(
      i18nString("Client Certificate file (*.p12, *.pfx)"),
      "p12",
      "pfx",
    )
    certFileChooser.setAcceptAllFileFilterUsed(false)
    return labeled(i18nString("Type of certificate file:"), certificateTypeCombo)
  }

  private fun createCertificatePathSetting(): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    val chooseButton = JButton(i18nString("choose..."))
    chooseButton.addActionListener {
      try {
        if (certFileChooser.showOpenDialog(owner) != NativeFileChooser.APPROVE_OPTION)
          return@addActionListener
        certificatePathField.text = certFileChooser.getSelectedFile().path
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    panel.add(certificatePathField)
    panel.add(chooseButton)
    return labeled(i18nString("Certificate file:"), panel)
  }

  @Throws(Exception::class)
  private fun createAppliedServers(): JComponent {
    // TODO: 任意のホスト名も選べるようにする
    val servers = owner.modelServices.servers.queryAll()
    servers.forEach { serverCombo.addItem(it.toString()) }
    serverCombo.maximumRowCount = servers.size
    return labeled(i18nString("Applied server:"), serverCombo)
  }

  private fun labeled(text: String, component: JComponent): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    val label = JLabel(text)
    label.preferredSize = Dimension(240, label.maximumSize.height)
    panel.add(label)
    component.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
    panel.add(component)
    return panel
  }
}
