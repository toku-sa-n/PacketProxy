package packetproxy.gui

import java.awt.Dimension
import java.awt.event.ItemEvent
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import packetproxy.common.*
import packetproxy.model.InterceptOption
import packetproxy.model.InterceptOption.Direction
import packetproxy.model.InterceptOption.Method
import packetproxy.model.InterceptOption.Relationship
import packetproxy.util.errWithStackTrace

class GUIOptionInterceptDialog(private val owner: GUIMain) : JDialog(owner) {
  private val buttonCancel = JButton(i18nString("Cancel"))
  private val buttonSet = JButton(i18nString("Save"))
  private val directionCombo = JComboBox<String>()
  private val relationshipCombo = JComboBox<String>()
  private val methodCombo = JComboBox<String>()
  private val textPattern = JTextField()
  private val serverCombo = JComboBox<String>()
  private var interceptOption: InterceptOption? = null

  init {
    title = i18nString("Setting")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 250, rect.y + rect.height / 2 - 250, 500, 500)

    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(createDirectionSetting())
    panel.add(createRelationshipSetting())
    panel.add(createReplaceMethodSetting())
    panel.add(createPatternSetting())
    panel.add(createAppliedServers())
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

  @Throws(Exception::class)
  fun showDialog(preset: InterceptOption): InterceptOption? {
    applyPreset(preset)
    return showDialog()
  }

  @Throws(Exception::class)
  private fun applyPreset(preset: InterceptOption) {
    if (
      preset.getDirection() == Direction.ALL_THE_OTHER_REQUESTS ||
        preset.getDirection() == Direction.ALL_THE_OTHER_RESPONSES
    ) {
      directionCombo.removeAllItems()
      directionCombo.addItem(preset.getDirectionAsString())
      directionCombo.selectedIndex = 0
      relationshipCombo.removeAllItems()
      relationshipCombo.addItem(
        InterceptOption.getRelationshipAsString(Relationship.ARE_INTERCEPTED)
      )
      relationshipCombo.addItem(
        InterceptOption.getRelationshipAsString(Relationship.ARE_NOT_INTERCEPTED)
      )
      relationshipCombo.selectedItem = preset.getRelationshipAsString()
      methodCombo.isEnabled = false
      textPattern.isEnabled = false
      serverCombo.isEnabled = false
      return
    }
    directionCombo.selectedItem = preset.getDirectionAsString()
    relationshipCombo.selectedItem = preset.getRelationshipAsString()
    methodCombo.selectedItem = preset.getMethod()?.toString()
    textPattern.text = preset.getPattern().orEmpty()
    serverCombo.selectedItem = preset.getServerName(owner.modelServices.database)
  }

  private fun save() {
    try {
      var direction = InterceptOption.getDirection(directionCombo.selectedItem as String)
      var relationship = InterceptOption.getRelationship(relationshipCombo.selectedItem as String)
      var method = Method.UNDEFINED
      var pattern = ""
      if (relationship != Relationship.IS_INTERCEPTED_IF_REQUEST_WAS_INTERCEPTED) {
        method = Method.valueOf(methodCombo.selectedItem as String)
        pattern = textPattern.text
      }
      var serverName = serverCombo.selectedItem as String
      interceptOption =
        InterceptOption(
          direction,
          InterceptOption.Type.REQUEST,
          relationship,
          pattern,
          method,
          owner.modelServices.servers.queryByString(serverName),
        )
      dispose()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun createDirectionSetting(): JComponent {
    directionCombo.addItem(InterceptOption.getDirectionAsString(Direction.REQUEST))
    directionCombo.addItem(InterceptOption.getDirectionAsString(Direction.RESPONSE))
    directionCombo.selectedIndex = 0
    directionCombo.isEnabled = true
    directionCombo.maximumRowCount = 2
    directionCombo.addItemListener {
      if (it.stateChange != ItemEvent.SELECTED) return@addItemListener
      try {
        updateRelationship(it.item as String)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    return labelAndObject(i18nString("Direction:"), directionCombo)
  }

  private fun createRelationshipSetting(): JComponent {
    relationshipCombo.isEnabled = true
    relationshipCombo.addItemListener {
      if (it.stateChange != ItemEvent.SELECTED) return@addItemListener
      try {
        var matchable =
          it.item as String !=
            InterceptOption.getRelationshipAsString(
              Relationship.IS_INTERCEPTED_IF_REQUEST_WAS_INTERCEPTED
            )
        methodCombo.isEnabled = matchable
        textPattern.isEnabled = matchable
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    updateRelationship(InterceptOption.getDirectionAsString(Direction.REQUEST))
    return labelAndObject(i18nString("Action and Condition:"), relationshipCombo)
  }

  private fun updateRelationship(direction: String) {
    relationshipCombo.removeAllItems()
    if (
      direction == InterceptOption.getDirectionAsString(Direction.ALL_THE_OTHER_REQUESTS) ||
        direction == InterceptOption.getDirectionAsString(Direction.ALL_THE_OTHER_RESPONSES)
    ) {
      relationshipCombo.addItem(
        InterceptOption.getRelationshipAsString(Relationship.ARE_INTERCEPTED)
      )
      relationshipCombo.addItem(
        InterceptOption.getRelationshipAsString(Relationship.ARE_NOT_INTERCEPTED)
      )
      return
    }
    relationshipCombo.addItem(
      InterceptOption.getRelationshipAsString(Relationship.IS_INTERCEPTED_IF_IT_MATCHES)
    )
    relationshipCombo.addItem(
      InterceptOption.getRelationshipAsString(Relationship.IS_NOT_INTERCEPTED_IF_IT_MATCHES)
    )
    relationshipCombo.maximumRowCount = 2
    if (direction != InterceptOption.getDirectionAsString(Direction.RESPONSE)) return
    relationshipCombo.addItem(
      InterceptOption.getRelationshipAsString(
        Relationship.IS_INTERCEPTED_IF_REQUEST_WAS_INTERCEPTED
      )
    )
    relationshipCombo.maximumRowCount = 3
  }

  private fun createReplaceMethodSetting(): JComponent {
    methodCombo.addItem("SIMPLE")
    methodCombo.addItem("REGEX")
    methodCombo.addItem("BINARY")
    methodCombo.isEnabled = true
    methodCombo.maximumRowCount = 3
    return labelAndObject(i18nString("Pattern Type:"), methodCombo)
  }

  private fun createPatternSetting(): JComponent =
    labelAndObject(i18nString("Pattern:"), textPattern)

  @Throws(Exception::class)
  private fun createAppliedServers(): JComponent {
    serverCombo.addItem("*")
    val servers = owner.modelServices.servers.queryAll()
    servers.forEach { serverCombo.addItem(it.toString()) }
    serverCombo.isEnabled = true
    serverCombo.maximumRowCount = servers.size.coerceAtLeast(1)
    return labelAndObject(i18nString("Target Server:"), serverCombo)
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
