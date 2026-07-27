package packetproxy.gui

import javax.swing.*
import packetproxy.model.InterceptOption

class GUIOptionInterceptEditOthersDialog(owner: JFrame) : JDialog(owner) {
  fun showDialog(): InterceptOption? {
    isModal = true
    isVisible = true
    return null
  }

  fun showDialog(preset: InterceptOption): InterceptOption? {
    isModal = true
    isVisible = true
    return null
  }
}
