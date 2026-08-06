package packetproxy.gui

import java.awt.Component
import java.awt.Dimension
import java.awt.Insets
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.UIManager

open class CloseButtonTabbedPane : JTabbedPane() {
  private val closeIcon = GuiIcons.close()
  private val mouseoveredIcon = GuiIcons.closeHovered()

  init {
    UIManager.put("TabbedPane.tabInsets", Insets(0, 7, 0, 7))
  }

  override fun addTab(title: String?, content: Component?) {
    val tab =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.X_AXIS)
        isOpaque = false
        border = BorderFactory.createEmptyBorder(0, 0, 0, 0)
      }
    val button =
      JButton(closeIcon).apply {
        val size = Dimension(closeIcon.iconWidth + 1, closeIcon.iconHeight + 1)
        preferredSize = size
        minimumSize = size
        maximumSize = size
        addMouseListener(
          object : MouseAdapter() {
            override fun mouseClicked(event: MouseEvent) {
              removeTabAt(indexOfComponent(content))
            }

            override fun mouseEntered(event: MouseEvent) {
              icon = mouseoveredIcon
            }

            override fun mouseExited(event: MouseEvent) {
              icon = closeIcon
            }
          }
        )
      }
    tab.add(Box.createHorizontalStrut(8))
    tab.add(JLabel(title))
    tab.add(Box.createHorizontalStrut(7))
    tab.add(button)
    super.addTab(null, content)
    setTabComponentAt(tabCount - 1, tab)
  }
}
