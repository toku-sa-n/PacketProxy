package packetproxy.gui

import javax.swing.*
import packetproxy.model.CAs.PacketProxyCAPerUser

class GUIOptionImportCertificateAndPrivateKeyDialog(
  owner: JFrame,
  private val ca: PacketProxyCAPerUser,
) : JDialog(owner) {
  fun showDialog() {
    isModal = true
    isVisible = true
  }
}
