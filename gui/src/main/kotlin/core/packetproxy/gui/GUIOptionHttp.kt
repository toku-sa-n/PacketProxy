package packetproxy.gui

import java.awt.Component
import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel
import packetproxy.common.*
import packetproxy.model.ConfigString
import packetproxy.model.Configs
import packetproxy.util.errWithStackTrace

class GUIOptionHttp(configs: Configs) {
  private val combo = JComboBox<String>()
  private val configPriority = ConfigString(configs, "PriorityOrderOfHttpVersions")

  init {
    combo.prototypeDisplayValue = "xxxxxxx"
    combo.addItem("HTTP1")
    combo.addItem("HTTP2")
    combo.maximumRowCount = combo.itemCount
    var priority = configPriority.getString()
    if (priority.isNullOrEmpty()) {
      configPriority.setString("HTTP2")
      priority = configPriority.getString()
    }
    combo.selectedItem = priority
    combo.addItemListener { event ->
      try {
        if (event.stateChange != java.awt.event.ItemEvent.SELECTED || combo.selectedItem == null)
          return@addItemListener
        priority = combo.selectedItem as String
        configPriority.setString(priority)
        combo.selectedItem = priority
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    combo.maximumSize = Dimension(combo.preferredSize.width, combo.minimumSize.height)
  }

  fun createPanel(): JPanel {
    val panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    panel.add(combo)
    panel.add(JLabel(i18nString("has a high priority")))
    panel.alignmentX = Component.LEFT_ALIGNMENT
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), panel.maximumSize.height)
    return panel
  }
}
