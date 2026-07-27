package packetproxy.gui

import javax.swing.*
import packetproxy.model.OpenVPNForwardPort

class GUIOptionOpenVPNDialog(owner: JFrame) : JDialog(owner) {
  fun showDialog(): OpenVPNForwardPort? {
    isModal = true
    isVisible = true
    return null
  }

  fun showDialog(preset: OpenVPNForwardPort): OpenVPNForwardPort? {
    isModal = true
    isVisible = true
    return null
  }
}
