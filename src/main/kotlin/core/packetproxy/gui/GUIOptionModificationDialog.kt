package packetproxy.gui

import javax.swing.*
import packetproxy.model.Modification

class GUIOptionModificationDialog(owner: JFrame) : JDialog(owner) {
  fun showDialog(): Modification? {
    isModal = true
    isVisible = true
    return null
  }

  fun showDialog(preset: Modification): Modification? {
    isModal = true
    isVisible = true
    return null
  }
}
