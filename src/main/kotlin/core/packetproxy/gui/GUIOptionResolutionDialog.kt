package packetproxy.gui

import javax.swing.*
import packetproxy.model.Resolution

class GUIOptionResolutionDialog(owner: JFrame) : JDialog(owner) {
  fun showDialog(): Resolution {
    isModal = true
    isVisible = true
    return Resolution("", "", false, "")
  }

  fun showDialog(preset: Resolution): Resolution? {
    isModal = true
    isVisible = true
    return null
  }
}
