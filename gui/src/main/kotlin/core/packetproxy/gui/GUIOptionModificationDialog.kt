package packetproxy.gui

import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import packetproxy.common.*
import packetproxy.model.Modification
import packetproxy.util.errWithStackTrace

class GUIOptionModificationDialog(private val owner: GUIMain) : JDialog(owner) {
  private val buttonCancel = JButton(i18nString("Cancel"))
  private val buttonSet = JButton(i18nString("Save"))
  private val textPattern = JTextField()
  private val textReplaced = JTextField()
  private val textPath = JTextField()
  private val methodCombo = JComboBox<String>()
  private val serverCombo = JComboBox<String>()
  private val directionCombo = JComboBox<String>()
  private var modification: Modification? = null

  init {
    title = i18nString("Setting")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 250, rect.y + rect.height / 2 - 275, 500, 550)

    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(createReplaceMethodSetting())
    panel.add(createPatternSetting())
    panel.add(createReplacedSetting())
    panel.add(createPathSetting())
    panel.add(createTypeSetting())
    panel.add(createAppliedServers())
    panel.add(buttons())
    contentPane.add(panel)

    buttonCancel.addActionListener {
      modification = null
      dispose()
    }
    buttonSet.addActionListener {
      try {
        val direction = Modification.Direction.valueOf(directionCombo.selectedItem as String)
        val method = Modification.Method.valueOf(methodCombo.selectedItem as String)
        val serverStr = serverCombo.selectedItem as String
        modification =
          Modification(
            direction,
            textPattern.text,
            textReplaced.text,
            method,
            owner.modelServices.servers.queryByString(serverStr),
            textPath.text,
          )
        dispose()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  fun showDialog(): Modification? {
    isModal = true
    isVisible = true
    return modification
  }

  fun showDialog(preset: Modification): Modification? {
    textPattern.text = preset.getPattern()
    textReplaced.text = preset.getReplaced()
    textPath.text = preset.getPath()
    methodCombo.selectedItem = preset.getMethod()?.toString()
    directionCombo.selectedItem = preset.getDirection()?.toString()
    serverCombo.selectedItem = preset.getServerName(owner.modelServices.database)
    isModal = true
    isVisible = true
    return modification
  }

  private fun labelAndObject(labelName: String, obj: JComponent): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    val label = JLabel(labelName)
    label.preferredSize = Dimension(150, label.maximumSize.height)
    panel.add(label)
    obj.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
    panel.add(obj)
    return panel
  }

  private fun buttons(): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), buttonSet.maximumSize.height)
    panel.add(buttonCancel)
    panel.add(buttonSet)
    return panel
  }

  private fun createAppliedServers(): JComponent {
    serverCombo.addItem("*")
    val servers = owner.modelServices.servers.queryAll()
    servers.forEach { serverCombo.addItem(it.toString()) }
    serverCombo.isEnabled = true
    serverCombo.maximumRowCount = servers.size.coerceAtLeast(1)
    return labelAndObject(i18nString("Applied server:"), serverCombo)
  }

  private fun createTypeSetting(): JComponent {
    directionCombo.addItem("CLIENT_REQUEST")
    directionCombo.addItem("SERVER_RESPONSE")
    directionCombo.addItem("ALL")
    directionCombo.isEnabled = true
    directionCombo.maximumRowCount = 3
    return labelAndObject(i18nString("Direction:"), directionCombo)
  }

  private fun createReplaceMethodSetting(): JComponent {
    methodCombo.addItem("SIMPLE")
    methodCombo.addItem("REGEX")
    methodCombo.addItem("BINARY")
    methodCombo.isEnabled = true
    methodCombo.maximumRowCount = 3
    return labelAndObject("Method:", methodCombo)
  }

  private fun createPatternSetting(): JComponent =
    labelAndObject(i18nString("Pattern:"), textPattern)

  private fun createReplacedSetting(): JComponent = labelAndObject("Replaced:", textReplaced)

  private fun createPathSetting(): JComponent = labelAndObject(i18nString("Path") + ":", textPath)
}
