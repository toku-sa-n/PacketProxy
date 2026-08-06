package packetproxy.gui

import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSeparator
import packetproxy.common.*
import packetproxy.model.CAs.PacketProxyCAPerUser
import packetproxy.util.err
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class GUIOption(private val owner: GUIMain) {
  private val disposableListeners = mutableListOf<() -> Unit>()

  fun createPanel(): JComponent {
    disposableListeners.clear()
    val panel = JPanel()
    panel.background = Color.WHITE
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    val listenPorts = GUIOptionListenPorts(owner)
    track(listenPorts::dispose)
    addSection(
      panel,
      i18nString("Listen Ports"),
      i18nString("Set listen port and server that packets are forwarded to."),
      listenPorts.createPanel(),
    )
    val servers = GUIOptionServers(owner)
    track(servers::dispose)
    addSection(
      panel,
      i18nString("Servers"),
      i18nString("Set server and encode module to be used to encode packets."),
      servers.createPanel(),
    )
    val resolutions = GUIOptionResolutions(owner)
    track(resolutions::dispose)
    addSection(
      panel,
      i18nString("Hostname Resolutions"),
      i18nString("Set ip addr and server for DNS resolution."),
      resolutions.createPanel(),
    )
    panel.add(
      element(
        i18nString("Auto Modifications"),
        i18nString("Set pattern for auto packet modification."),
      )
    )
    val modifications = GUIOptionModifications(owner)
    track(modifications::dispose)
    panel.add(modifications.createPanel())
    panel.add(
      JLabel(i18nString("Hex calculator for binary pattern")).also {
        it.alignmentX = Component.LEFT_ALIGNMENT
      }
    )
    panel.add(GUIHexCalc().create())
    panel.add(separator())
    panel.add(element(i18nString("Intercept Rules"), ""))
    val interceptRule =
      JCheckBox(i18nString("Use these intercept rules")).also { checkbox ->
        checkbox.isSelected = owner.modelServices.interceptOptions.isEnabled()
        checkbox.alignmentX = Component.LEFT_ALIGNMENT
        checkbox.addActionListener {
          try {
            owner.modelServices.interceptOptions.setEnabled(checkbox.isSelected)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    panel.add(interceptRule)
    val intercepts = GUIOptionIntercepts(owner)
    track(intercepts::dispose)
    panel.add(intercepts.createPanel())
    panel.add(separator())
    val clientCerts = GUIOptionClientCertificate(owner)
    track(clientCerts::dispose)
    addSection(
      panel,
      i18nString("Client Certificates"),
      i18nString("Set client certificate to be used on SSL/TLS."),
      clientCerts.createPanel(),
    )
    val sessionProfiles = GUIOptionSessionProfile(owner)
    track(sessionProfiles::dispose)
    addSection(
      panel,
      i18nString("Session Profiles"),
      i18nString(
        "Set Authorization header profiles for resending requests with different sessions."
      ),
      sessionProfiles.createPanel(),
    )
    val sslPassThrough = GUIOptionSSLPassThrough(owner)
    track(sslPassThrough::dispose)
    addSection(
      panel,
      i18nString("SSL PassThrough"),
      i18nString(
        "Set HTTPS server that packets are forwarded to without analyzing. These settings are enabled only if 'HTTP_PROXY' type is used."
      ),
      sslPassThrough.createPanel(),
    )
    val privateDns =
      GUIOptionPrivateDNS(
        owner.coreServices.privateDns,
        owner.modelServices.configs,
        owner.modelServices.fontManager,
      )
    track(privateDns::dispose)
    addSection(
      panel,
      i18nString("Private DNS server"),
      i18nString("Use private DNS server that resolves server name to the IP address of this pc."),
      privateDns.getPanel(),
    )
    val openVpn = GUIOptionOpenVPN(owner)
    track(openVpn::dispose)
    addSection(
      panel,
      i18nString("OpenVPN Server with Docker"),
      i18nString(
        "Use OpenVPN Server as Docker Container to proxy HTTP/HTTPS without DNS Spoofing."
      ),
      openVpn.getPanel(),
    )
    addSection(
      panel,
      i18nString("Priority Order of HTTP Versions"),
      i18nString("Set order of priority between HTTP1 and HTTP2."),
      GUIOptionHttp(owner.modelServices.configs).createPanel(),
    )
    addSection(
      panel,
      i18nString("History Auto Prune"),
      i18nString(
        "Optionally delete oldest history packets when count or database size exceeds limits. Disabled by default."
      ),
      GUIOptionHistory(owner.modelServices.configs).createPanel(),
    )
    panel.add(title(i18nString("PacketProxy CA Certificates & Private Keys")))
    panel.add(createCaPanel())
    panel.add(separator())
    val charSets = GUIOptionCharSets(owner)
    track(charSets::dispose)
    addSection(
      panel,
      i18nString("Character encodings"),
      i18nString("Add/Remove character encodings to be used to display contents of packet."),
      charSets.createPanel(),
    )
    val extensions = GUIOptionExtensions(owner)
    track(extensions::dispose)
    addSection(
      panel,
      i18nString("Extensions"),
      i18nString("Enable/Disable loaded extensions"),
      extensions.createPanel(),
    )
    addSection(panel, i18nString("Fonts"), "", GUIOptionFonts(owner).createPanel())
    val hubServer = GUIOptionHubServer(owner)
    track(hubServer::dispose)
    addSection(
      panel,
      i18nString("Import/Export configs (Experimental)"),
      i18nString(
        "Import/Export configs by GET/POST http://localhost:32349/config with 'Authorization: [AccessToken]' header"
      ),
      hubServer.createPanel(),
    )
    return JScrollPane(panel).also { it.verticalScrollBar.unitIncrement = 16 }
  }

  fun dispose() {
    disposableListeners.toList().forEach { disposer ->
      try {
        disposer()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    disposableListeners.clear()
  }

  private fun track(disposer: () -> Unit) {
    disposableListeners.add(disposer)
  }

  private fun createCaPanel(): JPanel {
    val caPanel = JPanel()
    caPanel.background = Color.WHITE
    caPanel.layout = BoxLayout(caPanel, BoxLayout.X_AXIS)
    val exportable = owner.modelServices.caFactory.queryExportable()
    val caCombo = JComboBox<String>()
    exportable.forEach {
      caCombo.addItem(it.getUTF8Name())
      caCombo.isEnabled = true
    }
    caCombo.maximumRowCount = exportable.size
    caCombo.maximumSize = Dimension(caCombo.preferredSize.width, caCombo.minimumSize.height)
    val exportCertButton = JButton(i18nString("Export"))
    exportCertButton.addActionListener {
      val ca = owner.modelServices.caFactory.findByUTF8Name(caCombo.selectedItem as String).get()
      GUIOptionExportCertificateAndPrivateKeyDialog(owner, ca).showDialog()
    }
    val regenerateCertButton = JButton(i18nString("Regenerate"))
    regenerateCertButton.addActionListener {
      try {
        val name = caCombo.selectedItem.toString()
        val ca = owner.modelServices.caFactory.find(name).orElseThrow()
        val option =
          JOptionPane.showConfirmDialog(
            owner,
            String.format(i18nString("Regenerate %s?"), name),
            String.format(i18nString("Regenerate CA certificate"), name),
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE,
          )
        if (option == JOptionPane.YES_OPTION) {
          log("regenerate %s", name)
          ca.regenerateCA()
        }
      } catch (exp: Exception) {
        err("RegenerateCertButton Action Error: %s", exp.message)
      }
    }
    val importCertButton = JButton(i18nString("Import another certificate and private key"))
    importCertButton.addActionListener {
      val ca =
        owner.modelServices.caFactory.findByUTF8Name("PacketProxy per-user CA").get()
          as PacketProxyCAPerUser
      GUIOptionImportCertificateAndPrivateKeyDialog(owner, ca).showDialog()
    }
    caPanel.add(caCombo)
    caPanel.add(exportCertButton)
    caPanel.add(regenerateCertButton)
    caPanel.add(importCertButton)
    caPanel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), caPanel.maximumSize.height)
    caPanel.alignmentX = Component.LEFT_ALIGNMENT
    return caPanel
  }

  private fun addSection(panel: JPanel, title: String, description: String, content: JComponent) {
    panel.add(element(title, description))
    panel.add(content)
    panel.add(separator())
  }

  private fun element(titleText: String, description: String): JComponent {
    val panel = JPanel()
    panel.background = Color.WHITE
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(title(titleText))
    panel.add(
      JLabel(description).also {
        it.foreground = Color.BLACK
        it.maximumSize = Dimension(Short.MAX_VALUE.toInt(), it.minimumSize.height)
        it.alignmentX = Component.LEFT_ALIGNMENT
      }
    )
    panel.alignmentX = Component.LEFT_ALIGNMENT
    return panel
  }

  private fun title(text: String): JComponent =
    JLabel(text).also {
      it.foreground = TITLE_FOREGROUND_COLOR
      it.background = Color.WHITE
      it.font = owner.modelServices.fontManager.getUICaptionFont()
      it.maximumSize = Dimension(Short.MAX_VALUE.toInt(), it.minimumSize.height)
      it.alignmentX = Component.LEFT_ALIGNMENT
    }

  private fun separator() =
    JSeparator().also {
      it.foreground = Color.LIGHT_GRAY
      it.background = Color.LIGHT_GRAY
      it.isOpaque = true
      it.preferredSize = Dimension(0, 1)
      it.maximumSize = Dimension(Int.MAX_VALUE, 1)
      it.alignmentX = Component.LEFT_ALIGNMENT
    }

  companion object {
    private val TITLE_FOREGROUND_COLOR = Color(0, 238, 208)
  }
}
