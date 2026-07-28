package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.ImageIcon
import javax.swing.JLabel
import packetproxy.util.err

class GUIHistoryAutoScroll : JLabel(disabledIcon) {
  private var autoScrollEnabled = false

  init {
    addMouseListener(
      object : MouseAdapter() {
        override fun mouseReleased(event: MouseEvent) {
          doToggle()
        }
      }
    )
  }

  @Synchronized override fun isEnabled(): Boolean = autoScrollEnabled

  @Synchronized
  fun doToggle() {
    if (autoScrollEnabled) {
      doDisable()
      return
    }
    doEnable()
  }

  @Synchronized
  fun doEnable() {
    if (autoScrollEnabled) {
      return
    }
    icon = enabledIcon
    autoScrollEnabled = true
    err("Auto scrolling was turned ON!")
  }

  @Synchronized
  fun doDisable() {
    if (!autoScrollEnabled) {
      return
    }
    icon = disabledIcon
    autoScrollEnabled = false
    err("Auto scrolling was turned OFF")
  }

  companion object {
    private val disabledIcon =
      ImageIcon(GUIHistoryAutoScroll::class.java.getResource("/gui/auto_scroll_disabled.png"))
    private val enabledIcon =
      ImageIcon(GUIHistoryAutoScroll::class.java.getResource("/gui/auto_scroll_enabled.png"))
  }
}
