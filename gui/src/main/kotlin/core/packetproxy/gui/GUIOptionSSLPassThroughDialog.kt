package packetproxy.gui

import javax.swing.*
import packetproxy.model.SSLPassThrough

class GUIOptionSSLPassThroughDialog(owner: JFrame) : JDialog(owner) {
  fun showDialog(): SSLPassThrough? {
    isModal = true
    isVisible = true
    return null
  }

  fun showDialog(preset: SSLPassThrough): SSLPassThrough? {
    isModal = true
    isVisible = true
    return null
  }
}
