package packetproxy.gui

import java.awt.Component
import java.awt.Dimension
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import packetproxy.common.*
import packetproxy.util.errWithStackTrace

class GUIOptionFonts(private val owner: GUIMain) {
  private lateinit var uiFontInfo: JTextField
  private lateinit var fontInfo: JTextField

  fun createPanel(): JPanel {
    uiFontInfo = createFontInfo(true)
    val uiButton = JButton(i18nString("choose..."))
    uiButton.addMouseListener(fontListener(true, false))
    val uiRestore = JButton(i18nString("restore default"))
    uiRestore.addMouseListener(fontListener(true, true))
    val uiPanel = createRow(i18nString("UI Font:"), uiFontInfo, uiButton, uiRestore)

    fontInfo = createFontInfo(false)
    val button = JButton(i18nString("choose..."))
    button.addMouseListener(fontListener(false, false))
    val restore = JButton(i18nString("restore default"))
    restore.addMouseListener(fontListener(false, true))
    val fontPanel = createRow(i18nString("Data Font:"), fontInfo, button, restore)

    val panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(uiPanel)
    panel.add(fontPanel)
    panel.alignmentX = Component.LEFT_ALIGNMENT
    return panel
  }

  private fun createFontInfo(isUi: Boolean): JTextField {
    val font =
      if (isUi) owner.modelServices.fontManager.getUIFont()
      else owner.modelServices.fontManager.getFont()
    val info = JTextField("${font.name} (size: ${font.size})")
    info.isEditable = false
    info.maximumSize = Dimension(Short.MAX_VALUE.toInt(), info.minimumSize.height)
    return info
  }

  private fun fontListener(isUi: Boolean, restore: Boolean) =
    object : MouseAdapter() {
      override fun mousePressed(e: MouseEvent) {
        try {
          val manager = owner.modelServices.fontManager
          if (restore) {
            if (isUi) manager.restoreUIFont() else manager.restoreFont()
          } else {
            val current = if (isUi) manager.getUIFont() else manager.getFont()
            val chooser = JFontChooser(current)
            if (chooser.showDialog(owner) != JFontChooser.OK_OPTION) {
              return
            }
            if (isUi) manager.setUIFont(chooser.getSelectedFont())
            else manager.setFont(chooser.getSelectedFont())
          }
          val field = if (isUi) uiFontInfo else fontInfo
          val font = if (isUi) manager.getUIFont() else manager.getFont()
          field.text = "${font.name} (size: ${font.size})"
          // 再起動せずに新しいフォントを反映する
          if (isUi) owner.refreshUiFont()
        } catch (ex: Exception) {
          errWithStackTrace(ex)
        }
      }
    }

  private fun createRow(
    label: String,
    field: JTextField,
    button: JButton,
    restore: JButton,
  ): JPanel {
    val panel = JPanel()
    panel.background = ThemeColors.panelBackground()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    panel.add(JLabel(label))
    panel.add(field)
    panel.add(button)
    panel.add(restore)
    return panel
  }
}
