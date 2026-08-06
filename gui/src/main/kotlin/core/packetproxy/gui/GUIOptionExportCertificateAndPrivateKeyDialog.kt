package packetproxy.gui

import java.awt.CardLayout
import java.awt.Component
import java.awt.Dimension
import java.io.File
import java.io.FileNotFoundException
import javax.swing.BoxLayout
import javax.swing.ButtonGroup
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JRadioButton
import packetproxy.common.i18nString
import packetproxy.model.CAs.CA
import packetproxy.util.errWithStackTrace

class GUIOptionExportCertificateAndPrivateKeyDialog(private val owner: JFrame, private val ca: CA) :
  JDialog(owner) {
  private val cardPanel = JPanel()
  private val cardLayout = CardLayout()

  init {
    title = i18nString("Export %s", ca.getName())
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 400, rect.y + rect.height / 2 - 250, 800, 500)
    cardPanel.layout = cardLayout
    cardPanel.add(createSelectPanel(), SELECT_PANEL)
    cardPanel.add(createP12PasswordPanel(), P12_PASSWORD_PANEL)
    contentPane.add(cardPanel)
  }

  fun showDialog() {
    isModal = true
    isVisible = true
  }

  private fun createSelectPanel(): JPanel {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    val chooseWhatToExport = JLabel(i18nString("Choose what you want to export"))
    val certificateGuide =
      JLabel(
        i18nString(
          "Export CA certificate used to view SSL packets. It needs to be registered in trusted CA list of Mac/Windows/Linux/Android/iOS"
        )
      )
    panel.add(chooseWhatToExport)
    panel.add(certificateGuide)
    val certificatePEMButton = JRadioButton(i18nString("Certificate(PEM format)"))
    val certificateDERButton = JRadioButton(i18nString("Certificate(DER format)"))
    val privateKeyPEMButton = JRadioButton(i18nString("Private Key(PEM format)"))
    val privateKeyDERButton = JRadioButton(i18nString("Private Key(DER format)"))
    val p12Button = JRadioButton(i18nString("Certificate&Private Key(P12 format)"))
    val buttonGroup = ButtonGroup()
    buttonGroup.add(certificatePEMButton)
    buttonGroup.add(certificateDERButton)
    buttonGroup.add(privateKeyPEMButton)
    buttonGroup.add(privateKeyDERButton)
    buttonGroup.add(p12Button)
    panel.add(certificatePEMButton)
    panel.add(certificateDERButton)
    panel.add(privateKeyPEMButton)
    panel.add(privateKeyDERButton)
    panel.add(p12Button)
    val buttons = JPanel()
    buttons.layout = BoxLayout(buttons, BoxLayout.X_AXIS)
    val cancelButton = JButton(i18nString("Cancel"))
    val nextButton = JButton(i18nString("Next"))
    buttons.maximumSize = Dimension(Short.MAX_VALUE.toInt(), cancelButton.maximumSize.height)
    buttons.add(cancelButton)
    buttons.add(nextButton)
    panel.add(buttons)
    cancelButton.addActionListener { dispose() }
    nextButton.addActionListener {
      val fileExtension =
        when {
          certificatePEMButton.isSelected || certificateDERButton.isSelected -> "crt"
          privateKeyPEMButton.isSelected || privateKeyDERButton.isSelected -> "key"
          p12Button.isSelected -> {
            cardLayout.show(cardPanel, P12_PASSWORD_PANEL)
            return@addActionListener
          }
          else -> return@addActionListener
        }
      exportToChosenFile(fileExtension) { path ->
        when {
          certificatePEMButton.isSelected -> ca.exportCertificatePEM(path)
          certificateDERButton.isSelected -> ca.exportCertificateDER(path)
          privateKeyPEMButton.isSelected -> ca.exportPrivateKeyPEM(path)
          privateKeyDERButton.isSelected -> ca.exportPrivateKeyDER(path)
        }
      }
    }
    listOf<JComponent>(
        chooseWhatToExport,
        certificateGuide,
        certificatePEMButton,
        certificateDERButton,
        privateKeyPEMButton,
        privateKeyDERButton,
        p12Button,
        buttons,
      )
      .forEach { it.alignmentX = Component.LEFT_ALIGNMENT }
    return panel
  }

  private fun createP12PasswordPanel(): JPanel {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    val p12PasswordField = JPasswordField()
    val p12PasswordComponent = labeled(i18nString("Password_of_p12_file:"), p12PasswordField)
    panel.add(p12PasswordComponent)
    val buttons = JPanel()
    buttons.layout = BoxLayout(buttons, BoxLayout.X_AXIS)
    val cancelButton = JButton(i18nString("Cancel"))
    val nextButton = JButton(i18nString("Next"))
    buttons.maximumSize = Dimension(Short.MAX_VALUE.toInt(), cancelButton.maximumSize.height)
    buttons.add(cancelButton)
    buttons.add(nextButton)
    panel.add(buttons)
    cancelButton.addActionListener {
      p12PasswordField.text = ""
      cardLayout.show(cardPanel, SELECT_PANEL)
    }
    nextButton.addActionListener {
      exportToChosenFile("p12") { path -> ca.exportP12(path, p12PasswordField.password) }
    }
    p12PasswordComponent.alignmentX = Component.LEFT_ALIGNMENT
    buttons.alignmentX = Component.LEFT_ALIGNMENT
    return panel
  }

  private fun exportToChosenFile(fileExtension: String, export: (path: String) -> Unit) {
    val fileChooser = WriteFileChooserWrapper(owner, fileExtension)
    fileChooser.addFileChooserListener(
      object : WriteFileChooserWrapper.FileChooserListener {
        override fun onApproved(file: File, extension: String) {
          try {
            val path = file.absolutePath
            export(path)
            JOptionPane.showMessageDialog(owner, i18nString("Successfully exported to %s", path))
            dispose()
          } catch (_: FileNotFoundException) {
            JOptionPane.showMessageDialog(owner, i18nString("[Error] no such directory."))
          } catch (e: Exception) {
            JOptionPane.showMessageDialog(owner, i18nString("[Error] failed to export."))
            errWithStackTrace(e)
          }
        }

        override fun onCanceled() {}

        override fun onError() {
          JOptionPane.showMessageDialog(owner, i18nString("[Error] failed to export."))
        }
      }
    )
    fileChooser.showSaveDialog()
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

  private companion object {
    const val SELECT_PANEL = "select panel"
    const val P12_PASSWORD_PANEL = "p12 password panel"
  }
}
