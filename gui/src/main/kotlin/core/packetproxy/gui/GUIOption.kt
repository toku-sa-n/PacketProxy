package packetproxy.gui

import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Component
import java.awt.Dimension
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSeparator
import javax.swing.ListSelectionModel
import javax.swing.border.EmptyBorder
import packetproxy.common.*
import packetproxy.model.CAs.PacketProxyCAPerUser
import packetproxy.util.err
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class GUIOption(private val owner: GUIMain) {
  private val disposableListeners = mutableListOf<() -> Unit>()
  private val builtCategories = mutableSetOf<String>()
  private var categoryList: JList<String>? = null

  fun createPanel(): JComponent {
    dispose()
    builtCategories.clear()
    val categories = createCategories()
    val contentPanel = JPanel(CardLayout())
    contentPanel.background = ThemeColors.panelBackground()
    val list = createCategoryList(categories, contentPanel)
    categoryList = list
    val panel = JPanel(BorderLayout())
    panel.background = ThemeColors.panelBackground()
    panel.add(createSidebar(list), BorderLayout.WEST)
    panel.add(contentPanel, BorderLayout.CENTER)
    list.selectedIndex = 0
    return panel
  }

  /** 他の画面からOptionsの特定カテゴリを開くために使う。 */
  fun selectCategory(title: String) {
    val list = categoryList ?: return
    val model = list.model
    for (index in 0 until model.size) {
      if (model.getElementAt(index) != title) {
        continue
      }
      list.selectedIndex = index
      list.ensureIndexIsVisible(index)
      return
    }
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

  private fun createCategoryList(
    categories: List<OptionCategory>,
    contentPanel: JPanel,
  ): JList<String> {
    val listModel = DefaultListModel<String>()
    categories.forEach { listModel.addElement(it.title) }
    val categoryList = JList(listModel)
    categoryList.selectionMode = ListSelectionModel.SINGLE_SELECTION
    categoryList.background = ThemeColors.panelBackground()
    categoryList.border = EmptyBorder(4, 4, 4, 4)
    categoryList.addListSelectionListener { event ->
      if (event.valueIsAdjusting) {
        return@addListSelectionListener
      }
      val index = categoryList.selectedIndex
      if (index < 0) {
        return@addListSelectionListener
      }
      showCategory(contentPanel, categories[index])
    }
    return categoryList
  }

  private fun createSidebar(categoryList: JList<String>): JComponent {
    val scrollPane = JScrollPane(categoryList)
    scrollPane.border = BorderFactory.createMatteBorder(0, 0, 0, 1, ThemeColors.separatorColor())
    scrollPane.preferredSize = Dimension(SIDEBAR_WIDTH, 0)
    scrollPane.minimumSize = Dimension(SIDEBAR_WIDTH, 0)
    scrollPane.verticalScrollBar.unitIncrement = 16
    return scrollPane
  }

  /** カテゴリの中身は初回表示時にだけ生成し、Optionsタブを開いた時の待ち時間を抑える。 */
  private fun showCategory(contentPanel: JPanel, category: OptionCategory) {
    val layout = contentPanel.layout as CardLayout
    if (builtCategories.contains(category.title)) {
      layout.show(contentPanel, category.title)
      return
    }
    try {
      contentPanel.add(createCategoryPanel(category), category.title)
      builtCategories.add(category.title)
      layout.show(contentPanel, category.title)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun createCategoryPanel(category: OptionCategory): JComponent {
    val panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.border = EmptyBorder(10, 10, 10, 10)
    val sections = category.sections()
    sections.forEachIndexed { index, section ->
      if (index > 0) {
        panel.add(separator())
      }
      panel.add(element(section.title, section.description))
      section.content.alignmentX = Component.LEFT_ALIGNMENT
      panel.add(section.content)
    }
    return JScrollPane(panel).also { it.verticalScrollBar.unitIncrement = 16 }
  }

  private fun createCategories(): List<OptionCategory> =
    listOf(
      OptionCategory(i18nString("Listen Ports")) { listOf(createListenPortsSection()) },
      OptionCategory(i18nString("Servers")) { listOf(createServersSection()) },
      OptionCategory(i18nString("Hostname Resolutions")) { listOf(createResolutionsSection()) },
      OptionCategory(i18nString("SSL PassThrough")) { listOf(createSSLPassThroughSection()) },
      OptionCategory(i18nString("Private DNS server")) { listOf(createPrivateDnsSection()) },
      OptionCategory(i18nString("OpenVPN")) { listOf(createOpenVpnSection()) },
      OptionCategory(i18nString("HTTP")) { listOf(createHttpSection()) },
      OptionCategory(i18nString("Auto Modifications")) { listOf(createModificationsSection()) },
      OptionCategory(i18nString("Intercept Rules")) { listOf(createInterceptsSection()) },
      OptionCategory(i18nString("Client Certificates")) { listOf(createClientCertsSection()) },
      OptionCategory(i18nString("CA Certificates")) { listOf(createCaSection()) },
      OptionCategory(i18nString("Session Profiles")) { listOf(createSessionProfilesSection()) },
      OptionCategory(i18nString("History Auto Prune")) { listOf(createHistorySection()) },
      OptionCategory(i18nString("Character encodings")) { listOf(createCharSetsSection()) },
      OptionCategory(i18nString("Appearance")) { createAppearanceSections() },
      OptionCategory(i18nString("Extensions")) { listOf(createExtensionsSection()) },
      OptionCategory(i18nString("Tools")) { listOf(createToolsSection()) },
      OptionCategory(i18nString("Import/Export")) { listOf(createHubServerSection()) },
    )

  private fun createListenPortsSection(): OptionSection {
    val listenPorts = GUIOptionListenPorts(owner)
    track(listenPorts::dispose)
    return OptionSection(
      i18nString("Listen Ports"),
      i18nString("Set listen port and server that packets are forwarded to."),
      listenPorts.createPanel(),
    )
  }

  private fun createServersSection(): OptionSection {
    val servers = GUIOptionServers(owner)
    track(servers::dispose)
    return OptionSection(
      i18nString("Servers"),
      i18nString("Set server and encode module to be used to encode packets."),
      servers.createPanel(),
    )
  }

  private fun createResolutionsSection(): OptionSection {
    val resolutions = GUIOptionResolutions(owner)
    track(resolutions::dispose)
    return OptionSection(
      i18nString("Hostname Resolutions"),
      i18nString("Set ip addr and server for DNS resolution."),
      resolutions.createPanel(),
    )
  }

  private fun createSSLPassThroughSection(): OptionSection {
    val sslPassThrough = GUIOptionSSLPassThrough(owner)
    track(sslPassThrough::dispose)
    return OptionSection(
      i18nString("SSL PassThrough"),
      i18nString(
        "Set HTTPS server that packets are forwarded to without analyzing. These settings are enabled only if 'HTTP_PROXY' type is used."
      ),
      sslPassThrough.createPanel(),
    )
  }

  private fun createPrivateDnsSection(): OptionSection {
    val privateDns =
      GUIOptionPrivateDNS(
        owner.coreServices.privateDns,
        owner.modelServices.configs,
        owner.modelServices.fontManager,
      )
    track(privateDns::dispose)
    return OptionSection(
      i18nString("Private DNS server"),
      i18nString("Use private DNS server that resolves server name to the IP address of this pc."),
      privateDns.getPanel(),
    )
  }

  private fun createOpenVpnSection(): OptionSection {
    val openVpn = GUIOptionOpenVPN(owner)
    track(openVpn::dispose)
    return OptionSection(
      i18nString("OpenVPN Server with Docker"),
      i18nString(
        "Use OpenVPN Server as Docker Container to proxy HTTP/HTTPS without DNS Spoofing."
      ),
      openVpn.getPanel(),
    )
  }

  private fun createHttpSection(): OptionSection =
    OptionSection(
      i18nString("Priority Order of HTTP Versions"),
      i18nString("Set order of priority between HTTP1 and HTTP2."),
      GUIOptionHttp(owner.modelServices.configs).createPanel(),
    )

  private fun createModificationsSection(): OptionSection {
    val modifications = GUIOptionModifications(owner)
    track(modifications::dispose)
    return OptionSection(
      i18nString("Auto Modifications"),
      i18nString("Set pattern for auto packet modification."),
      modifications.createPanel(),
    )
  }

  private fun createInterceptsSection(): OptionSection {
    val interceptRule =
      JCheckBox(i18nString("Use these intercept rules")).also { checkbox ->
        checkbox.isSelected = owner.modelServices.interceptOptions.isEnabled()
        checkbox.background = ThemeColors.panelBackground()
        checkbox.addActionListener {
          try {
            owner.modelServices.interceptOptions.setEnabled(checkbox.isSelected)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    val intercepts = GUIOptionIntercepts(owner)
    track(intercepts::dispose)
    return OptionSection(
      i18nString("Intercept Rules"),
      "",
      verticalBox(interceptRule, intercepts.createPanel()),
    )
  }

  private fun createClientCertsSection(): OptionSection {
    val clientCerts = GUIOptionClientCertificate(owner)
    track(clientCerts::dispose)
    return OptionSection(
      i18nString("Client Certificates"),
      i18nString("Set client certificate to be used on SSL/TLS."),
      clientCerts.createPanel(),
    )
  }

  private fun createCaSection(): OptionSection =
    OptionSection(i18nString("PacketProxy CA Certificates & Private Keys"), "", createCaPanel())

  private fun createSessionProfilesSection(): OptionSection {
    val sessionProfiles = GUIOptionSessionProfile(owner)
    track(sessionProfiles::dispose)
    return OptionSection(
      i18nString("Session Profiles"),
      i18nString(
        "Set Authorization header profiles for resending requests with different sessions."
      ),
      sessionProfiles.createPanel(),
    )
  }

  private fun createHistorySection(): OptionSection =
    OptionSection(
      i18nString("History Auto Prune"),
      i18nString(
        "Optionally delete oldest history packets when count or database size exceeds limits. Disabled by default."
      ),
      GUIOptionHistory(owner.modelServices.configs).createPanel(),
    )

  private fun createCharSetsSection(): OptionSection {
    val charSets = GUIOptionCharSets(owner)
    track(charSets::dispose)
    return OptionSection(
      i18nString("Character encodings"),
      i18nString("Add/Remove character encodings to be used to display contents of packet."),
      charSets.createPanel(),
    )
  }

  /** テーマなど外観に関する設定はこのカテゴリに追加する。 */
  private fun createAppearanceSections(): List<OptionSection> =
    listOf(
      OptionSection(i18nString("Theme"), "", GUIOptionAppearance(owner).createPanel()),
      OptionSection(i18nString("Fonts"), "", GUIOptionFonts(owner).createPanel()),
    )

  private fun createExtensionsSection(): OptionSection {
    val extensions = GUIOptionExtensions(owner)
    track(extensions::dispose)
    return OptionSection(
      i18nString("Extensions"),
      i18nString("Enable/Disable loaded extensions"),
      extensions.createPanel(),
    )
  }

  private fun createToolsSection(): OptionSection =
    OptionSection(i18nString("Hex calculator for binary pattern"), "", GUIHexCalc().create())

  private fun createHubServerSection(): OptionSection {
    val hubServer = GUIOptionHubServer(owner)
    track(hubServer::dispose)
    return OptionSection(
      i18nString("Import/Export configs (Experimental)"),
      i18nString(
        "Import/Export configs by GET/POST http://localhost:32349/config with 'Authorization: [AccessToken]' header"
      ),
      hubServer.createPanel(),
    )
  }

  private fun track(disposer: () -> Unit) {
    disposableListeners.add(disposer)
  }

  private fun verticalBox(vararg components: JComponent): JComponent {
    val panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.alignmentX = Component.LEFT_ALIGNMENT
    components.forEach { component ->
      component.alignmentX = Component.LEFT_ALIGNMENT
      panel.add(component)
    }
    return panel
  }

  private fun createCaPanel(): JPanel {
    val caPanel = JPanel()
    caPanel.background = ThemeColors.panelBackground()
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

  private fun element(titleText: String, description: String): JComponent {
    val panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(title(titleText))
    if (description.isNotEmpty()) {
      panel.add(
        JLabel(description).also {
          it.foreground = ThemeColors.textForeground()
          it.maximumSize = Dimension(Short.MAX_VALUE.toInt(), it.minimumSize.height)
          it.alignmentX = Component.LEFT_ALIGNMENT
        }
      )
    }
    panel.alignmentX = Component.LEFT_ALIGNMENT
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), panel.minimumSize.height)
    return panel
  }

  private fun title(text: String): JComponent =
    JLabel(text).also {
      it.foreground = ThemeColors.sectionTitleForeground()
      it.background = ThemeColors.panelBackground()
      it.font = owner.modelServices.fontManager.getUICaptionFont()
      it.maximumSize = Dimension(Short.MAX_VALUE.toInt(), it.minimumSize.height)
      it.alignmentX = Component.LEFT_ALIGNMENT
    }

  private fun separator() =
    JSeparator().also {
      it.foreground = ThemeColors.separatorColor()
      it.background = ThemeColors.separatorColor()
      it.isOpaque = true
      it.preferredSize = Dimension(0, 1)
      it.maximumSize = Dimension(Int.MAX_VALUE, 1)
      it.alignmentX = Component.LEFT_ALIGNMENT
    }

  private class OptionSection(val title: String, val description: String, val content: JComponent)

  private class OptionCategory(val title: String, val sections: () -> List<OptionSection>)

  companion object {
    private const val SIDEBAR_WIDTH = 200
  }
}
