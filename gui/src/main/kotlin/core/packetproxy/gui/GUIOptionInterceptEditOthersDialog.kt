package packetproxy.gui

import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import packetproxy.common.*
import packetproxy.model.InterceptOption
import packetproxy.model.InterceptOption.Direction
import packetproxy.model.InterceptOption.Method
import packetproxy.model.InterceptOption.Relationship
import packetproxy.util.errWithStackTrace

class GUIOptionInterceptEditOthersDialog(owner: GUIMain) : JDialog(owner) {
  private val buttonCancel = JButton(i18nString("Cancel"))
  private val buttonSet = JButton(i18nString("Save"))
  private val directionCombo = JComboBox<String>()
  private val relationshipCombo = JComboBox<String>()
  private var interceptOption: InterceptOption? = null

  init {
    title = i18nString("Setting")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 250, rect.y + rect.height / 2 - 250, 500, 500)

    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(createDirectionSetting())
    panel.add(createRelationshipSetting())
    panel.add(buttons())
    contentPane.add(panel)

    buttonCancel.addActionListener {
      interceptOption = null
      dispose()
    }
    buttonSet.addActionListener { save() }
  }

  fun showDialog(): InterceptOption? {
    isModal = true
    isVisible = true
    return interceptOption
  }

  fun showDialog(preset: InterceptOption): InterceptOption? {
    directionCombo.selectedItem = preset.getDirectionAsString()
    relationshipCombo.selectedItem = preset.getRelationshipAsString()
    return showDialog()
  }

  private fun save() {
    try {
      var direction = InterceptOption.getDirection(directionCombo.selectedItem as String)
      var relationship = InterceptOption.getRelationship(relationshipCombo.selectedItem as String)
      interceptOption =
        InterceptOption(
          direction,
          InterceptOption.Type.REQUEST,
          relationship,
          "",
          Method.UNDEFINED,
          null,
        )
      dispose()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun createDirectionSetting(): JComponent {
    directionCombo.addItem(InterceptOption.getDirectionAsString(Direction.ALL_THE_OTHER_REQUESTS))
    directionCombo.addItem(InterceptOption.getDirectionAsString(Direction.ALL_THE_OTHER_RESPONSES))
    directionCombo.selectedIndex = 0
    directionCombo.isEnabled = false
    directionCombo.maximumRowCount = 2
    return labelAndObject(i18nString("Direction:"), directionCombo)
  }

  private fun createRelationshipSetting(): JComponent {
    relationshipCombo.addItem(InterceptOption.getRelationshipAsString(Relationship.ARE_INTERCEPTED))
    relationshipCombo.addItem(
      InterceptOption.getRelationshipAsString(Relationship.ARE_NOT_INTERCEPTED)
    )
    relationshipCombo.selectedIndex = 0
    relationshipCombo.isEnabled = true
    relationshipCombo.maximumRowCount = 2
    return labelAndObject(i18nString("Action and Condition:"), relationshipCombo)
  }

  private fun buttons(): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), buttonSet.maximumSize.height)
    panel.add(buttonCancel)
    panel.add(buttonSet)
    return panel
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
}
