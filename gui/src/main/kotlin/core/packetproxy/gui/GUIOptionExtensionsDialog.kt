package packetproxy.gui

import java.awt.Container
import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import packetproxy.common.*
import packetproxy.model.Extension
import packetproxy.util.errWithStackTrace

class GUIOptionExtensionsDialog(private val owner: JFrame) : JDialog(owner) {
  private val cancel = JButton(i18nString("Cancel"))
  private val save = JButton(i18nString("Save"))
  private val nameField = HintTextField("sample library")
  private val pathField = HintTextField("path/to/library.jar")
  private var extension: Extension? = null

  init {
    title = i18nString("Setting")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 250, rect.y + rect.height / 2 - 250, 500, 500)
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(labeled(i18nString("Library Name"), nameField))
    panel.add(labeled(i18nString("Library Path"), pathField))
    panel.add(buttons())
    (contentPane as Container).add(panel)
    save.addActionListener {
      try {
        val name = nameField.text
        if (name.isNotEmpty())
          extension = owner.modelServices.extensions.loadExtension(name, pathField.text)
        dispose()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    cancel.addActionListener { dispose() }
  }

  @Throws(Exception::class)
  fun showDialog(preset: Extension): Extension? {
    nameField.text = preset.getName()
    nameField.isEditable = false
    pathField.text = preset.getPath()
    isModal = true
    isVisible = true
    return extension
  }

  fun showDialog(): Extension? {
    isModal = true
    isVisible = true
    return extension
  }

  private fun labeled(labelText: String, component: JComponent): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    val label = JLabel(labelText)
    label.preferredSize = Dimension(150, label.maximumSize.height)
    panel.add(label)
    component.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
    panel.add(component)
    return panel
  }

  private fun buttons(): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), save.maximumSize.height)
    panel.add(cancel)
    panel.add(save)
    return panel
  }
}
