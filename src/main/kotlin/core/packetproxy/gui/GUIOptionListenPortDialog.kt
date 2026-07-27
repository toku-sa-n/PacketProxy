package packetproxy.gui

import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTextField
import packetproxy.common.I18nString
import packetproxy.model.CAFactory
import packetproxy.model.ListenPort
import packetproxy.model.Server
import packetproxy.model.Servers
import packetproxy.util.Logging.errWithStackTrace

class GUIOptionListenPortDialog(owner: JFrame) : JDialog(owner) {
  private val port = JTextField()
  private val servers = JComboBox<String>()
  private val types = JComboBox<String>()
  private val cas = JComboBox<String>()
  private var result: ListenPort? = null
  private var lastServer: String? = null

  init {
    title = I18nString.get("Listenning Port Setting")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 300, rect.y + rect.height / 2 - 200, 600, 400)
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(labeled("Listen Port:", port))
    panel.add(labeled("Type:", types))
    panel.add(labeled(I18nString.get("Forward to:"), servers))
    panel.add(labeled(I18nString.get("CA certificate to sign:"), cas))
    val buttons = JPanel()
    buttons.layout = BoxLayout(buttons, BoxLayout.X_AXIS)
    val cancel = JButton(I18nString.get("Cancel"))
    val save = JButton(I18nString.get("Save"))
    buttons.add(cancel)
    buttons.add(save)
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
      if (it.stateChange == java.awt.event.ItemEvent.SELECTED) updateNextHopList(it.item as String)
    }
    servers.addItemListener {
      if (
        it.stateChange == java.awt.event.ItemEvent.SELECTED &&
          types.selectedItem !in
            setOf("HTTP_PROXY", "SSL_TRANSPARENT_PROXY", "HTTP_TRANSPARENT_PROXY")
      )
        lastServer = it.item as? String
    }
    CAFactory.queryAll().forEach { cas.addItem(it.getUTF8Name()) }
    cas.selectedItem = "PacketProxy per-user CA"
    updateNextHopList("HTTP_PROXY")
    cancel.addActionListener {
      result = null
      dispose()
    }
    save.addActionListener {
      try {
        val type = ListenPort.TYPE.valueOf(types.selectedItem as String)
        val ca =
          CAFactory.findByUTF8Name(cas.selectedItem as String)
            .map { it.getName() ?: "Error" }
            .orElse("Error")
        result =
          ListenPort(
            port.text.toInt(),
            type,
            Servers.getInstance().queryByString((servers.selectedItem as? String) ?: ""),
            ca,
          )
        dispose()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  @Throws(Exception::class)
  fun showDialog(preset: ListenPort): ListenPort? {
    port.text = preset.getPort().toString()
    types.selectedItem = preset.getType().toString()
    preset.getServer()?.let { servers.selectedItem = it.toString() }
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

  private fun updateNextHopList(type: String) {
    try {
      val selected = lastServer
      servers.removeAllItems()
      val candidates: List<Server> =
        when (type) {
          "HTTP_PROXY" -> {
            servers.addItem(I18nString.get("Forward to server directly without upstream proxy"))
            Servers.getInstance().queryHttpProxies()
          }
          "SSL_TRANSPARENT_PROXY" -> {
            servers.addItem(I18nString.get("Forward to server specified in SNI header"))
            Servers.getInstance().queryHttpProxies()
          }
          "HTTP_TRANSPARENT_PROXY" -> {
            servers.addItem(I18nString.get("Forward to server specified in Hosts header"))
            Servers.getInstance().queryHttpProxies()
          }
          "QUIC_TRANSPARENT_PROXY" -> {
            servers.addItem(I18nString.get("Forward to server specified in SNI header"))
            emptyList()
          }
          else -> Servers.getInstance().queryNonHttpProxies()
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
          I18nString.get("Set server you wish to connect into 'Servers setting' first."),
        )
      candidates.forEach { servers.addItem(it.toString()) }
      selected?.let { servers.selectedItem = it }
      servers.maximumRowCount = servers.itemCount
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
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
