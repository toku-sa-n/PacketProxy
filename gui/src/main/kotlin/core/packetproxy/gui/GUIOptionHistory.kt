package packetproxy.gui

import java.awt.Component
import java.awt.Dimension
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.SpinnerNumberModel
import packetproxy.common.i18nString
import packetproxy.model.ConfigBoolean
import packetproxy.model.ConfigInteger
import packetproxy.model.Configs
import packetproxy.model.Packets
import packetproxy.util.errWithStackTrace

class GUIOptionHistory(configs: Configs) {
  private val enabled = ConfigBoolean(configs, Packets.KEY_AUTO_PRUNE_ENABLED)
  private val maxPackets = ConfigInteger(configs, Packets.KEY_AUTO_PRUNE_MAX_PACKETS, "100000")
  private val maxDbMb = ConfigInteger(configs, Packets.KEY_AUTO_PRUNE_MAX_DB_MB, "1024")

  private val enableCheckbox =
    JCheckBox(i18nString("Automatically prune old history packets")).also {
      it.isSelected = enabled.getState()
      it.alignmentX = Component.LEFT_ALIGNMENT
    }
  private val maxPacketsSpinner =
    JSpinner(
      SpinnerNumberModel(maxPackets.getInteger().coerceAtLeast(1000), 1000, 10_000_000, 1000)
    )
  private val maxDbMbSpinner =
    JSpinner(SpinnerNumberModel(maxDbMb.getInteger().coerceAtLeast(64), 64, 10_000, 64))

  init {
    enableCheckbox.addActionListener {
      try {
        enabled.setState(enableCheckbox.isSelected)
        updateEnabledState()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    maxPacketsSpinner.addChangeListener {
      try {
        maxPackets.setInteger(maxPacketsSpinner.value as Int)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    maxDbMbSpinner.addChangeListener {
      try {
        maxDbMb.setInteger(maxDbMbSpinner.value as Int)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    updateEnabledState()
  }

  fun createPanel(): JPanel {
    val panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(enableCheckbox)
    panel.add(Box.createVerticalStrut(8))
    panel.add(row(i18nString("Max packets"), maxPacketsSpinner))
    panel.add(Box.createVerticalStrut(4))
    panel.add(row(i18nString("Max database size (MB)"), maxDbMbSpinner))
    panel.alignmentX = Component.LEFT_ALIGNMENT
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), panel.preferredSize.height)
    return panel
  }

  private fun row(label: String, spinner: JSpinner): JPanel {
    val row = JPanel()
    row.background = ThemeColors.panelBackground()
    row.layout = BoxLayout(row, BoxLayout.X_AXIS)
    row.alignmentX = Component.LEFT_ALIGNMENT
    row.add(JLabel(label))
    row.add(Box.createHorizontalStrut(8))
    spinner.maximumSize = Dimension(120, spinner.preferredSize.height)
    row.add(spinner)
    row.add(Box.createHorizontalGlue())
    return row
  }

  private fun updateEnabledState() {
    val on = enableCheckbox.isSelected
    maxPacketsSpinner.isEnabled = on
    maxDbMbSpinner.isEnabled = on
  }
}
