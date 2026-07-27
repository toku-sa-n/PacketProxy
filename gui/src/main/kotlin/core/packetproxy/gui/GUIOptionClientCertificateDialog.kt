package packetproxy.gui

import javax.swing.*
import packetproxy.model.ClientCertificate

class GUIOptionClientCertificateDialog(private val owner: JFrame) : JDialog(owner) {
  fun showDialog(): ClientCertificate? {
    isModal = true
    isVisible = true
    return null
  }

  fun showDialog(preset: ClientCertificate): ClientCertificate? {
    isModal = true
    isVisible = true
    return null
  }
}
