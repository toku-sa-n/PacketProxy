package packetproxy.gui

import javax.swing.*
import packetproxy.model.CAs.CA

class GUIOptionExportCertificateAndPrivateKeyDialog(owner: JFrame, private val ca: CA) :
  JDialog(owner) {
  fun showDialog() {
    isModal = true
    isVisible = true
  }
}
