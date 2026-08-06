package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JLabel
import packetproxy.common.i18nString
import packetproxy.util.log

class GUIHistoryAutoScroll : JLabel(disabledIcon) {
  private var autoScrollEnabled = false

  init {
    toolTipText = i18nString("Toggle auto scroll to the newest packet")
    addMouseListener(
      object : MouseAdapter() {
        override fun mouseReleased(event: MouseEvent) {
          doToggle()
        }
      }
    )
  }

  @Synchronized fun isAutoScrollEnabled(): Boolean = autoScrollEnabled

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
    log("Auto scrolling was turned ON!")
  }

  @Synchronized
  fun doDisable() {
    if (!autoScrollEnabled) {
      return
    }
    icon = disabledIcon
    autoScrollEnabled = false
    log("Auto scrolling was turned OFF")
  }

  companion object {
    private val disabledIcon = GuiIcons.autoScrollDisabled()
    private val enabledIcon = GuiIcons.autoScrollEnabled()
  }
}
