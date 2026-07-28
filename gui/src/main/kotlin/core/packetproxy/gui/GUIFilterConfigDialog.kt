package packetproxy.gui

import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import javax.swing.*
import packetproxy.common.*

class GUIFilterConfigDialog(private val owner: JFrame) : JDialog(owner) {
  init {
    title = i18nString("Manage filters")
    addWindowListener(
      object : WindowAdapter() {
        override fun windowClosing(e: WindowEvent) {
          dispose()
        }
      }
    )
    var rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 400, rect.y + rect.height / 2 - 250, 800, 500)
    contentPane.add(
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(GUIFilterConfig(owner).createPanel())
      }
    )
  }

  fun showDialog() {
    isModal = true
    isVisible = true
  }
}
