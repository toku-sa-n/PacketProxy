package packetproxy.gui

import java.awt.Dimension
import javax.swing.*
import packetproxy.common.*
import packetproxy.model.RegexParam

class GUIRegexParamDialog(private val owner: JFrame) : JDialog(owner) {
  private var cancel = JButton(i18nString("Cancel"))
  private var save = JButton(i18nString("Save"))
  private var regex = JTextField()
  private var nameField = JTextField()
  private var regexParam: RegexParam? = null

  init {
    title = i18nString("RegexParam setting")
    var rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 250, rect.y + rect.height / 2 - 250, 500, 500)
    var panel =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(labelAndObject(i18nString("Param Name:"), nameField))
        add(labelAndObject(i18nString("regex to pickup"), regex))
        add(buttons())
      }
    contentPane.add(panel)
    cancel.addActionListener {
      regexParam = null
      dispose()
    }
    save.addActionListener {
      regexParam = RegexParam(regexParam!!.getPacketId(), nameField.text, regex.text)
      dispose()
    }
  }

  fun showDialog(value: RegexParam): RegexParam? {
    regexParam = value
    regex.text = value.getRegex()
    nameField.text = value.getName()
    isModal = true
    isVisible = true
    return regexParam
  }

  fun showDialog(): RegexParam? {
    isModal = true
    isVisible = true
    return regexParam
  }

  private fun labelAndObject(labelName: String, component: JComponent): JComponent {
    var label = JLabel(labelName).apply { preferredSize = Dimension(150, maximumSize.height) }
    return JPanel().apply {
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(label)
      component.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
      add(component)
    }
  }

  private fun buttons(): JComponent =
    JPanel().apply {
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      maximumSize = Dimension(Short.MAX_VALUE.toInt(), save.maximumSize.height)
      add(cancel)
      add(save)
    }
}
