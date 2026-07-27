package packetproxy.gui

import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSeparator
import packetproxy.common.FontManager
import packetproxy.common.I18nString

class GUIOption(private val owner: JFrame) {
  fun createPanel(): JComponent {
    val panel = JPanel()
    panel.background = Color.WHITE
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    addSection(
      panel,
      "Listen Ports",
      I18nString.get("Set listen port and server that packets are forwarded to."),
      GUIOptionListenPorts(owner).createPanel(),
    )
    addSection(
      panel,
      "Servers",
      I18nString.get("Set server and encode module to be used to encode packets."),
      GUIOptionServers(owner).createPanel(),
    )
    addSection(
      panel,
      "Hostname Resolutions",
      I18nString.get("Set ip addr and server for DNS resolution."),
      GUIOptionResolutions(owner).createPanel(),
    )
    addSection(
      panel,
      "Auto Modifications",
      I18nString.get("Set pattern for auto packet modification."),
      GUIOptionModifications(owner).createPanel(),
    )
    panel.add(JLabel(I18nString.get("Hex calculator for binary pattern")))
    panel.add(GUIHexCalc().create())
    addSection(panel, "Intercept Rules", "", GUIOptionIntercepts(owner).createPanel())
    addSection(
      panel,
      "Client Certificates",
      I18nString.get("Set client certificate to be used on SSL/TLS."),
      GUIOptionClientCertificate(owner).createPanel(),
    )
    addSection(
      panel,
      I18nString.get("Session Profiles"),
      I18nString.get(
        "Set Authorization header profiles for resending requests with different sessions."
      ),
      GUIOptionSessionProfile(owner).createPanel(),
    )
    addSection(
      panel,
      "SSL PassThrough",
      I18nString.get(
        "Set HTTPS server that packets are forwarded to without analyzing. These settings are enabled only if 'HTTP_PROXY' type is used."
      ),
      GUIOptionSSLPassThrough(owner).createPanel(),
    )
    addSection(
      panel,
      "Private DNS server",
      I18nString.get(
        "Use private DNS server that resolves server name to the IP address of this pc."
      ),
      GUIOptionPrivateDNS().getPanel(),
    )
    addSection(
      panel,
      "OpenVPN Server with Docker",
      I18nString.get(
        "Use OpenVPN Server as Docker Container to proxy HTTP/HTTPS without DNS Spoofing."
      ),
      GUIOptionOpenVPN(owner).getPanel(),
    )
    addSection(
      panel,
      "Priority Order of HTTP Versions",
      I18nString.get("Set order of priority between HTTP1 and HTTP2."),
      GUIOptionHttp().createPanel(),
    )
    addSection(
      panel,
      "Character encodings",
      I18nString.get("Add/Remove character encodings to be used to display contents of packet."),
      GUIOptionCharSets(owner).createPanel(),
    )
    addSection(
      panel,
      "Extensions",
      I18nString.get("Enable/Disable loaded extensions"),
      GUIOptionExtensions(owner).createPanel(),
    )
    addSection(panel, "Fonts", "", GUIOptionFonts(owner).createPanel())
    addSection(
      panel,
      "Import/Export configs (Experimental)",
      I18nString.get(
        "Import/Export configs by GET/POST http://localhost:32349/config with 'Authorization: [AccessToken]' header"
      ),
      GUIOptionHubServer(owner).createPanel(),
    )
    return JScrollPane(panel).also { it.verticalScrollBar.unitIncrement = 16 }
  }

  private fun addSection(panel: JPanel, title: String, description: String, content: JComponent) {
    panel.add(element(title, description))
    panel.add(content)
    panel.add(separator())
  }

  private fun element(title: String, description: String): JComponent {
    val panel = JPanel()
    panel.background = Color.WHITE
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(
      JLabel(title).also {
        it.foreground = Color(0, 238, 208)
        it.font = FontManager.getInstance().getUICaptionFont()
        it.maximumSize = Dimension(Short.MAX_VALUE.toInt(), it.minimumSize.height)
        it.alignmentX = Component.LEFT_ALIGNMENT
      }
    )
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

  private fun separator() =
    JSeparator().also {
      it.foreground = Color.LIGHT_GRAY
      it.background = Color.LIGHT_GRAY
      it.isOpaque = true
      it.preferredSize = Dimension(0, 1)
      it.maximumSize = Dimension(Int.MAX_VALUE, 1)
    }
}
