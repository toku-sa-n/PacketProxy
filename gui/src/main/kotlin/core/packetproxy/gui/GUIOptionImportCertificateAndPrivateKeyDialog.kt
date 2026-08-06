package packetproxy.gui

import java.awt.CardLayout
import java.awt.Component
import java.awt.Dimension
import java.io.FileNotFoundException
import java.io.IOException
import java.nio.file.NoSuchFileException
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
import javax.swing.JTextField
import packetproxy.common.i18nString
import packetproxy.model.CAs.PacketProxyCAPerUser
import packetproxy.util.errWithStackTrace

class GUIOptionImportCertificateAndPrivateKeyDialog(
  owner: JFrame,
  private val ca: PacketProxyCAPerUser,
) : JDialog(owner) {
  private val cardPanel = JPanel()
  private val cardLayout = CardLayout()

  init {
    title = i18nString("Import certificate and private key")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 400, rect.y + rect.height / 2 - 250, 800, 500)
    cardPanel.layout = cardLayout
    cardPanel.add(createSelectPanel(), SELECT_PANEL)
    cardPanel.add(
      createImportPanel(
        i18nString("Certificate file (*.crt, *.pem)"),
        arrayOf("crt", "pem"),
        i18nString("Private Key file (*.key, *.pem)"),
        arrayOf("key", "pem"),
        ca::importPEM,
      ),
      PEM_PANEL,
    )
    cardPanel.add(
      createImportPanel(
        i18nString("Certificate file (*.crt, *.der)"),
        arrayOf("crt", "der"),
        i18nString("Private Key file (*.key, *.der)"),
        arrayOf("key", "der"),
        ca::importDER,
      ),
      DER_PANEL,
    )
    cardPanel.add(createImportP12Panel(), P12_PANEL)
    contentPane.add(cardPanel)
  }

  fun showDialog() {
    isModal = true
    isVisible = true
  }

  private fun createSelectPanel(): JPanel {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    val chooseImportType = JLabel(i18nString("Choose import type"))
    val importCaution =
      JLabel(
        i18nString(
          "Importing overwrite PacketProxy per-user CA, so please export in advance if necessary"
        )
      )
    panel.add(chooseImportType)
    panel.add(importCaution)
    val pemButton = JRadioButton(i18nString("Certificate(PEM format)+Private Key(PEM format)"))
    val derButton = JRadioButton(i18nString("Certificate(DER format)+Private Key(DER format)"))
    val p12Button = JRadioButton(i18nString("Certificate&Private Key(P12 format)"))
    val buttonGroup = ButtonGroup()
    buttonGroup.add(pemButton)
    buttonGroup.add(derButton)
    buttonGroup.add(p12Button)
    panel.add(pemButton)
    panel.add(derButton)
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
      when {
        pemButton.isSelected -> cardLayout.show(cardPanel, PEM_PANEL)
        derButton.isSelected -> cardLayout.show(cardPanel, DER_PANEL)
        p12Button.isSelected -> cardLayout.show(cardPanel, P12_PANEL)
      }
    }
    listOf<JComponent>(chooseImportType, importCaution, pemButton, derButton, p12Button, buttons)
      .forEach { it.alignmentX = Component.LEFT_ALIGNMENT }
    return panel
  }

  private fun createImportPanel(
    certificateFilterName: String,
    certificateExtensions: Array<String>,
    privateKeyFilterName: String,
    privateKeyExtensions: Array<String>,
    import: (certificatePath: String, privateKeyPath: String) -> Unit,
  ): JPanel {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    val certificatePathField = JTextField()
    val privateKeyPathField = JTextField()
    panel.add(
      labeled(
        i18nString("Certificate file:"),
        fileChooserField(certificatePathField, certificateFilterName, *certificateExtensions),
      )
    )
    panel.add(
      labeled(
        i18nString("Private Key file:"),
        fileChooserField(privateKeyPathField, privateKeyFilterName, *privateKeyExtensions),
      )
    )
    val buttons = JPanel()
    buttons.layout = BoxLayout(buttons, BoxLayout.X_AXIS)
    val backButton = JButton(i18nString("Back"))
    val importButton = JButton(i18nString("Import"))
    buttons.add(backButton)
    buttons.add(importButton)
    buttons.maximumSize = Dimension(Short.MAX_VALUE.toInt(), backButton.maximumSize.height)
    panel.add(buttons)
    backButton.addActionListener {
      certificatePathField.text = ""
      privateKeyPathField.text = ""
      cardLayout.show(cardPanel, SELECT_PANEL)
    }
    importButton.addActionListener {
      if (certificatePathField.text.isEmpty() || privateKeyPathField.text.isEmpty())
        return@addActionListener
      try {
        import(certificatePathField.text, privateKeyPathField.text)
        JOptionPane.showMessageDialog(cardPanel, i18nString("Successfully imported"))
        dispose()
      } catch (_: NoSuchFileException) {
        JOptionPane.showMessageDialog(cardPanel, i18nString("[Error] no such file."))
      } catch (_: FileNotFoundException) {
        JOptionPane.showMessageDialog(cardPanel, i18nString("[Error] no such file."))
      } catch (e: Exception) {
        JOptionPane.showMessageDialog(cardPanel, i18nString("[Error] failed to import."))
        errWithStackTrace(e)
      }
    }
    return panel
  }

  private fun createImportP12Panel(): JPanel {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    val p12PathField = JTextField()
    val p12PasswordField = JPasswordField()
    panel.add(
      labeled(
        i18nString("P12 file:"),
        fileChooserField(p12PathField, i18nString("P12 file (*.p12, *.pfx)"), "p12", "pfx"),
      )
    )
    panel.add(labeled(i18nString("Password of p12 file:"), p12PasswordField))
    val buttons = JPanel()
    buttons.layout = BoxLayout(buttons, BoxLayout.X_AXIS)
    val backButton = JButton(i18nString("Back"))
    val importButton = JButton(i18nString("Import"))
    buttons.add(backButton)
    buttons.add(importButton)
    buttons.maximumSize = Dimension(Short.MAX_VALUE.toInt(), backButton.maximumSize.height)
    panel.add(buttons)
    backButton.addActionListener {
      p12PathField.text = ""
      p12PasswordField.text = ""
      cardLayout.show(cardPanel, SELECT_PANEL)
    }
    importButton.addActionListener {
      if (p12PathField.text.isEmpty()) return@addActionListener
      try {
        ca.importP12(p12PathField.text, p12PasswordField.password)
        JOptionPane.showMessageDialog(cardPanel, i18nString("Successfully imported"))
        dispose()
      } catch (_: NoSuchFileException) {
        JOptionPane.showMessageDialog(cardPanel, i18nString("[Error] no such file."))
      } catch (_: IOException) {
        JOptionPane.showMessageDialog(cardPanel, i18nString("[Error] incorrect p12file password."))
      } catch (e: Exception) {
        JOptionPane.showMessageDialog(cardPanel, i18nString("[Error] failed to import."))
        errWithStackTrace(e)
      }
    }
    return panel
  }

  private fun fileChooserField(
    pathField: JTextField,
    filterName: String,
    vararg extensions: String,
  ): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    panel.add(pathField)
    val chooseButton = JButton(i18nString("choose..."))
    chooseButton.addActionListener {
      try {
        val chooser = NativeFileChooser()
        chooser.addChoosableFileFilter(filterName, *extensions)
        chooser.setAcceptAllFileFilterUsed(false)
        if (chooser.showOpenDialog(panel) != NativeFileChooser.APPROVE_OPTION)
          return@addActionListener
        pathField.text = chooser.getSelectedFile().path
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    panel.add(chooseButton)
    return panel
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
    const val PEM_PANEL = "import pem panel"
    const val DER_PANEL = "import der panel"
    const val P12_PANEL = "import p12 panel"
  }
}
