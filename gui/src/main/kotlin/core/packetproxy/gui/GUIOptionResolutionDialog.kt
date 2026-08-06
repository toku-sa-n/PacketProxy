package packetproxy.gui

import java.awt.Dimension
import java.awt.EventQueue
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.JPanel
import packetproxy.common.i18nString
import packetproxy.model.Resolution

class GUIOptionResolutionDialog(owner: JFrame) : JDialog(owner) {
  private val ip = HintTextField(i18nString("(ex.) 127.0.0.1"))
  private val hostName = HintTextField(i18nString("(ex.) example.com"))
  private val comment = HintTextField(i18nString("(ex.) game server for test"))
  private val enabled = JCheckBox(i18nString("Override"))
  private val cancel = JButton(i18nString("Cancel"))
  private val save = JButton(i18nString("Save"))
  private var result: Resolution? = null

  init {
    title = i18nString("Resolution setting")
    var panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(labeledRow(i18nString("ip:"), ip))
    panel.add(labeledRow(i18nString("host:"), hostName))
    panel.add(labeledRow(i18nString("enabled:"), enabled))
    panel.add(labeledRow(i18nString("Comments:"), comment))
    var footer = JPanel()
    footer.layout = BoxLayout(footer, BoxLayout.X_AXIS)
    footer.maximumSize = Dimension(Short.MAX_VALUE.toInt(), save.maximumSize.height)
    footer.add(cancel)
    footer.add(save)
    panel.add(footer)
    contentPane.add(panel)
    installDefaultActions(
      this,
      save,
      cancel,
      onSave = {
        result = Resolution(ip.text, hostName.text, enabled.isSelected, comment.text)
        dispose()
      },
      onCancel = {
        result = null
        dispose()
      },
    )
    packWithMinSize(this, MIN_WIDTH, MIN_HEIGHT)
    centerOver(owner)
  }

  fun showDialog(preset: Resolution): Resolution? {
    ip.text = preset.getIp()
    hostName.text = preset.getHostName()
    enabled.isSelected = preset.isEnabled()
    comment.text = preset.getComment()
    isModal = true
    isVisible = true
    result?.let {
      preset.setIp(ip.text)
      preset.setHostName(hostName.text)
      preset.setEnabled(enabled.isSelected)
      preset.setComment(comment.text)
      return preset
    }
    return null
  }

  fun showDialog(): Resolution? {
    EventQueue.invokeLater { cancel.requestFocusInWindow() }
    isModal = true
    isVisible = true
    return result
  }

  companion object {
    private const val MIN_WIDTH = 700
    private const val MIN_HEIGHT = 500
  }
}
