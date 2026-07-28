package packetproxy.gui

import java.awt.Dimension
import javax.swing.*
import packetproxy.common.*
import packetproxy.model.Filter
import packetproxy.util.errWithStackTrace

class GUIFilterConfigEditDialog(private val owner: JFrame, private var filter: Filter) :
  JDialog(owner) {
  private var cancel = JButton(i18nString("Cancel"))
  private var update = JButton(i18nString("Update"))
  private var nameField = JTextField(filter.getName())
  private var content =
    JTextArea(filter.getFilter()).apply {
      lineWrap = true
      wrapStyleWord = true
    }

  init {
    title = i18nString("Setting")
    var rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 350, rect.y + rect.height / 2 - 125, 700, 250)
    contentPane.add(
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(row(i18nString("Filter name:"), nameField, 2))
        add(row(i18nString("Filter:"), content, 5))
        add(
          JPanel().apply {
            add(cancel)
            add(update)
          }
        )
      }
    )
    cancel.addActionListener { dispose() }
    update.addActionListener {
      try {
        var value = requireNotNull(owner.modelServices.filters.query(filter.getId()))
        value.setName(nameField.text)
        value.setFilter(content.text)
        owner.modelServices.filters.update(value)
        dispose()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  fun showDialog() {
    isModal = true
    isVisible = true
  }

  private fun row(labelText: String, item: JComponent, height: Int): JComponent {
    var label = JLabel(labelText).apply { preferredSize = Dimension(150, maximumSize.height) }
    return JPanel().apply {
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(label)
      item.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * height)
      add(item)
    }
  }
}
