package packetproxy.gui

import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JDialog
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTextField
import packetproxy.common.*
import packetproxy.model.ListenPort
import packetproxy.model.Server
import packetproxy.util.errWithStackTrace

class GUIOptionListenPortDialog(private val owner: GUIMain) : JDialog(owner) {
  private val port = JTextField()
  private val servers = JComboBox<String>()
  private val types = JComboBox<String>()
  private val cas = JComboBox<String>()
  private var result: ListenPort? = null
  private var lastServer: String? = null

  init {
    title = i18nString("Listenning Port Setting")
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(labeledRow(i18nString(PORT_LABEL), port))
    panel.add(labeledRow(i18nString("Type:"), types))
    panel.add(labeledRow(i18nString("Forward to:"), servers))
    panel.add(labeledRow(i18nString("CA certificate to sign:"), cas))
    val buttons = JPanel()
    buttons.layout = BoxLayout(buttons, BoxLayout.X_AXIS)
    val cancelButton = JButton(i18nString("Cancel"))
    val saveButton = JButton(i18nString("Save"))
    buttons.add(cancelButton)
    buttons.add(saveButton)
    panel.add(buttons)
    contentPane.add(panel)
    for (type in
      arrayOf(
        "HTTP_PROXY",
        "FORWARDER",
        "SSL_FORWARDER",
        "SSL_TRANSPARENT_PROXY",
        "HTTP_TRANSPARENT_PROXY",
        "UDP_FORWARDER",
        "QUIC_FORWARDER",
        "QUIC_TRANSPARENT_PROXY",
        "XMPP_SSL_FORWARDER",
      )) types.addItem(type)
    types.maximumRowCount = types.itemCount
    types.addItemListener {
      if (it.stateChange != java.awt.event.ItemEvent.SELECTED) return@addItemListener
      updateNextHopList(it.item as String)
      updateTypeDescription(it.item as String)
    }
    servers.addItemListener {
      if (
        it.stateChange == java.awt.event.ItemEvent.SELECTED &&
          types.selectedItem !in
            setOf("HTTP_PROXY", "SSL_TRANSPARENT_PROXY", "HTTP_TRANSPARENT_PROXY")
      )
        lastServer = it.item as? String
    }
    owner.modelServices.caFactory.queryAll().forEach { cas.addItem(it.getUTF8Name()) }
    cas.selectedItem = "PacketProxy per-user CA"
    updateNextHopList("HTTP_PROXY")
    updateTypeDescription("HTTP_PROXY")
    installDefaultActions(
      this,
      saveButton,
      cancelButton,
      onSave = { save() },
      onCancel = {
        result = null
        dispose()
      },
    )
    packWithMinSize(this, MIN_WIDTH, MIN_HEIGHT)
    centerOver(owner)
  }

  @Throws(Exception::class)
  fun showDialog(preset: ListenPort): ListenPort? {
    port.text = preset.getPort().toString()
    types.selectedItem = preset.getType().toString()
    preset.getServer(owner.modelServices.database)?.let { servers.selectedItem = it.toString() }
    cas.selectedItem = preset.getCA().get().getUTF8Name()
    isModal = true
    isVisible = true
    return result
  }

  fun showDialog(): ListenPort? {
    isModal = true
    isVisible = true
    return result
  }

  private fun save() {
    val portNumber = PortValidator.parse(port.text)
    if (portNumber == null) {
      JOptionPane.showMessageDialog(
        this,
        PortValidator.errorMessage(i18nString(PORT_LABEL)),
        i18nString("Error"),
        JOptionPane.ERROR_MESSAGE,
      )
      return
    }
    try {
      val type = ListenPort.TYPE.valueOf(types.selectedItem as String)
      val ca =
        owner.modelServices.caFactory
          .findByUTF8Name(cas.selectedItem as String)
          .map { it.getName() ?: "Error" }
          .orElse("Error")
      result =
        ListenPort(
          portNumber,
          type,
          owner.modelServices.servers.queryByString((servers.selectedItem as? String) ?: ""),
          ca,
        )
      dispose()
    } catch (e: Exception) {
      errWithStackTrace(e)
      JOptionPane.showMessageDialog(this, e.message, i18nString("Error"), JOptionPane.ERROR_MESSAGE)
    }
  }

  /** 選択されたListenポートの種類の説明をツールチップで表示する */
  private fun updateTypeDescription(type: String) {
    types.toolTipText = listenPortTypeDescription(type)
  }

  private fun listenPortTypeDescription(type: String): String =
    when (type) {
      "HTTP_PROXY" ->
        i18nString("Works as an HTTP/HTTPS proxy. Set this port as the proxy of the client.")
      "FORWARDER" -> i18nString("Forwards TCP packets to the server selected below.")
      "SSL_FORWARDER" ->
        i18nString("Forwards TCP packets to the server selected below over SSL/TLS.")
      "SSL_TRANSPARENT_PROXY" ->
        i18nString("Receives SSL/TLS packets transparently and forwards them by the SNI header.")
      "HTTP_TRANSPARENT_PROXY" ->
        i18nString("Receives HTTP packets transparently and forwards them by the Host header.")
      "UDP_FORWARDER" -> i18nString("Forwards UDP packets to the server selected below.")
      "QUIC_FORWARDER" -> i18nString("Forwards QUIC packets to the server selected below.")
      "QUIC_TRANSPARENT_PROXY" ->
        i18nString("Receives QUIC packets transparently and forwards them by the SNI header.")
      "XMPP_SSL_FORWARDER" ->
        i18nString("Forwards XMPP packets to the server selected below, starting with STARTTLS.")
      else -> ""
    }

  private fun updateNextHopList(type: String) {
    try {
      val selected = lastServer
      servers.removeAllItems()
      val candidates: List<Server> =
        when (type) {
          "HTTP_PROXY" -> {
            servers.addItem(i18nString("Forward to server directly without upstream proxy"))
            owner.modelServices.servers.queryHttpProxies()
          }
          "SSL_TRANSPARENT_PROXY" -> {
            servers.addItem(i18nString("Forward to server specified in SNI header"))
            owner.modelServices.servers.queryHttpProxies()
          }
          "HTTP_TRANSPARENT_PROXY" -> {
            servers.addItem(i18nString("Forward to server specified in Hosts header"))
            owner.modelServices.servers.queryHttpProxies()
          }
          "QUIC_TRANSPARENT_PROXY" -> {
            servers.addItem(i18nString("Forward to server specified in SNI header"))
            emptyList()
          }
          else -> owner.modelServices.servers.queryNonHttpProxies()
        }
      if (
        candidates.isEmpty() &&
          type !in
            setOf(
              "HTTP_PROXY",
              "SSL_TRANSPARENT_PROXY",
              "HTTP_TRANSPARENT_PROXY",
              "QUIC_TRANSPARENT_PROXY",
            )
      )
        JOptionPane.showMessageDialog(
          this,
          i18nString("Set server you wish to connect into 'Servers setting' first."),
        )
      candidates.forEach { servers.addItem(it.toString()) }
      selected?.let { servers.selectedItem = it }
      servers.maximumRowCount = servers.itemCount
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  companion object {
    private const val PORT_LABEL = "Listen Port:"
    private const val MIN_WIDTH = 600
    private const val MIN_HEIGHT = 400
  }
}
