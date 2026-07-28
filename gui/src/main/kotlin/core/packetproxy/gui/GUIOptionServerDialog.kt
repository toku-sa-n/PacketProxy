package packetproxy.gui

import java.awt.Dimension
import java.awt.EventQueue
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import packetproxy.common.*
import packetproxy.model.Server

class GUIOptionServerDialog(private val owner: GUIMain) : JDialog(owner) {
  private val ip = HintTextField("(ex.) aaa.bbb.ccc.com or 1.2.3.4")
  private val port = HintTextField("(ex.) 80")
  private val comment = HintTextField("(ex.) game server for test")
  private val ssl = JCheckBox(i18nString("Need a SSL/TLS to connect"))
  private val dns = JCheckBox(i18nString("Spoofing A Record"))
  private val dns6 = JCheckBox(i18nString("Spoofing AAAA Record"))
  private val upstream = JCheckBox(i18nString("Need to be defined as an Upstream Http Proxy"))
  private val encoders = JComboBox<String>()
  private val descriptor = JButton(i18nString("Import Proto File"))
  private lateinit var descriptorPanel: JPanel
  private var descriptorPath: String? = null
  private var editingServerId: Int? = null
  private var result: Server? = null

  init {
    title = i18nString("Server setting")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 350, rect.y + rect.height / 2 - 290, 700, 580)
    owner.coreServices.encoderManager.getEncoderNameList().forEach { encoders.addItem(it) }
    encoders.maximumRowCount = encoders.itemCount
    encoders.selectedItem = "HTTP"
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(labeled(i18nString("Server name:"), ip))
    panel.add(labeled(i18nString("Server port:"), port))
    panel.add(labeled(i18nString("Use SSL/TLS:"), ssl))
    panel.add(labeled(i18nString("Encode module:"), encoders))
    descriptorPanel = JPanel()
    descriptorPanel.layout = BoxLayout(descriptorPanel, BoxLayout.X_AXIS)
    descriptorPanel.add(JLabel(i18nString("gRPC descriptor (.desc):")))
    descriptorPanel.add(descriptor)
    descriptorPanel.add(Box.createHorizontalGlue())
    panel.add(descriptorPanel)
    panel.add(
      labeled(
        i18nString("DNS Spoofing:"),
        JLabel("Private DNS server needs to resolve the server name to local machine IP."),
      )
    )
    panel.add(labeled(" ", dns))
    panel.add(labeled(" ", dns6))
    panel.add(labeled(i18nString("Upstream HTTP Proxy:"), upstream))
    panel.add(labeled(i18nString("Comments:"), comment))
    val footer = JPanel()
    footer.layout = BoxLayout(footer, BoxLayout.X_AXIS)
    val cancel = JButton(i18nString("Cancel"))
    val save = JButton(i18nString("Save"))
    footer.add(cancel)
    footer.add(save)
    panel.add(footer)
    contentPane.add(panel)
    upstream.addActionListener { updateUpstreamState() }
    encoders.addActionListener { updateDescriptorVisibility() }
    descriptor.addActionListener {
      try {
        val outcome =
          GUIOptionGrpcDescriptorDialog(owner, editingServerId, descriptorPath, owner.modelServices)
            .showManageDialog()
        if (outcome.applied) descriptorPath = outcome.descriptorPath
      } catch (e: Exception) {
        JOptionPane.showMessageDialog(
          this,
          e.message,
          i18nString("Error"),
          JOptionPane.ERROR_MESSAGE,
        )
      }
    }
    cancel.addActionListener {
      result = null
      dispose()
    }
    save.addActionListener { save() }
    updateDescriptorVisibility()
  }

  fun showDialog(preset: Server): Server? {
    editingServerId = preset.getId()
    ip.text = preset.getIp()
    port.text = preset.getPort().toString()
    encoders.selectedItem = preset.getEncoder()
    ssl.isSelected = preset.getUseSSL()
    upstream.isSelected = preset.isHttpProxy()
    dns.isSelected = preset.isResolved()
    dns6.isSelected = preset.isResolved6()
    comment.text = preset.getComment()
    descriptorPath = preset.getDescriptorPath()?.takeIf { it.isNotEmpty() }
    updateUpstreamState()
    isModal = true
    isVisible = true
    result?.let {
      preset.setIp(ip.text)
      preset.setPort(port.text.toInt())
      preset.setEncoder(encoders.selectedItem as String)
      preset.setUseSSL(ssl.isSelected)
      preset.setResolved(dns.isSelected)
      preset.setResolved6(dns6.isSelected)
      preset.setHttpProxy(upstream.isSelected)
      preset.setComment(comment.text)
      preset.setDescriptorPath(descriptorPath?.trim()?.takeIf { path -> path.isNotEmpty() })
      return preset
    }
    return null
  }

  fun showDialog(): Server? {
    editingServerId = null
    descriptorPath = null
    updateDescriptorVisibility()
    EventQueue.invokeLater { cancelFocus() }
    isModal = true
    isVisible = true
    return result
  }

  private fun cancelFocus() {}

  private fun save() {
    if (ip.text.any { it.code !in 0x21..0x7e }) {
      JOptionPane.showMessageDialog(null, i18nString("The ServerName contains invalid characters."))
      return
    }
    result =
      Server(
        ip.text,
        port.text.toInt(),
        ssl.isSelected,
        encoders.selectedItem as String,
        dns.isSelected,
        dns6.isSelected,
        upstream.isSelected,
        comment.text,
      )
    result!!.setDescriptorPath(descriptorPath?.trim()?.takeIf { it.isNotEmpty() })
    dispose()
  }

  private fun updateUpstreamState() {
    val enabled = !upstream.isSelected
    if (!enabled) {
      encoders.selectedItem = "HTTP"
      ssl.isSelected = false
      dns.isSelected = false
      dns6.isSelected = false
    }
    encoders.isEnabled = enabled
    ssl.isEnabled = enabled
    dns.isEnabled = enabled
    dns6.isEnabled = enabled
    updateDescriptorVisibility()
  }

  private fun updateDescriptorVisibility() {
    descriptorPanel.isVisible =
      !upstream.isSelected && encoders.selectedItem in setOf("gRPC", "gRPC Streaming")
  }

  private fun labeled(text: String, component: JComponent): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    val label = JLabel(text)
    label.preferredSize = Dimension(150, label.maximumSize.height)
    panel.add(label)
    component.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
    panel.add(component)
    return panel
  }
}
