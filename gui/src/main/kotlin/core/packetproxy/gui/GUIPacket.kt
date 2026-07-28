package packetproxy.gui

import javax.swing.JComponent
import packetproxy.model.Packet

class GUIPacket(private val main: GUIMain) {
  private lateinit var requestResponsePanel: GUIRequestResponsePanel
  private var showingPacket: Packet? = null
  private var showingResponsePacket: Packet? = null

  fun createPanel(): JComponent {
    requestResponsePanel = GUIRequestResponsePanel(main)
    return requestResponsePanel.createPanel()
  }

  fun getData(): ByteArray = requestResponsePanel.getRequestData()

  fun update() {
    if (showingPacket == null && showingResponsePacket == null) {
      return
    }
    showingPacket?.let { requestResponsePanel.setRequestPacket(it) }
    showingResponsePacket?.let { requestResponsePanel.setResponsePacket(it) }
  }

  fun setPacket(packet: Packet?) {
    setSinglePacket(packet, false)
  }

  fun setPacket(packet: Packet?, forceRefresh: Boolean) {
    setSinglePacket(packet, forceRefresh)
  }

  fun setPackets(requestPacket: Packet?, responsePacket: Packet?) {
    setPackets(requestPacket, responsePacket, false)
  }

  fun setPackets(requestPacket: Packet?, responsePacket: Packet?, forceRefresh: Boolean) {
    if (!forceRefresh && isSameRequestResponse(requestPacket, responsePacket)) {
      return
    }
    showingPacket = requestPacket
    showingResponsePacket = responsePacket
    if (requestPacket != null) {
      requestResponsePanel.setPackets(requestPacket, responsePacket)
    }
  }

  fun setSinglePacket(packet: Packet?) {
    setSinglePacket(packet, false)
  }

  fun setSinglePacket(packet: Packet?, forceRefresh: Boolean) {
    if (!forceRefresh && isSameSinglePacket(packet)) {
      return
    }
    showingPacket = packet
    showingResponsePacket = null
    if (packet != null) {
      requestResponsePanel.setSinglePacket(packet)
    }
  }

  fun getPacket(): Packet = requireNotNull(showingPacket)

  fun getResponsePacket(): Packet = requireNotNull(showingResponsePacket)

  private fun isSameSinglePacket(packet: Packet?): Boolean =
    showingPacket != null &&
      showingResponsePacket == null &&
      showingPacket?.getId() == packet?.getId()

  private fun isSameRequestResponse(requestPacket: Packet?, responsePacket: Packet?): Boolean {
    if (
      showingPacket == null ||
        requestPacket == null ||
        showingPacket?.getId() != requestPacket.getId()
    ) {
      return false
    }
    if (showingResponsePacket == null || responsePacket == null) {
      return showingResponsePacket == null && responsePacket == null
    }
    return showingResponsePacket?.getId() == responsePacket.getId()
  }
}
