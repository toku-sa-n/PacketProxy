package packetproxy.gui

import java.awt.Dimension
import javax.swing.*
import packetproxy.common.*
import packetproxy.model.Filter
import packetproxy.util.errWithStackTrace

class GUIFilterConfigAddDialog(private val owner: JFrame, baseFilter: String = "") :
  JDialog(owner) {
  private var cancel = JButton(i18nString("Cancel"))
  private var add = JButton(i18nString("Add"))
  private var nameField = JTextField()
  private var filter =
    JTextArea().apply {
      lineWrap = true
      wrapStyleWord = true
      text = baseFilter
    }

  init {
    title = i18nString("Add a filter")
    var rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 350, rect.y + rect.height / 2 - 125, 700, 250)
    contentPane.add(
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(row(i18nString("Filter name:"), nameField, 2))
        add(row(i18nString("Filter:"), filter, 5))
        add(
          JPanel().apply {
            add(cancel)
            add(add)
          }
        )
      }
    )
    cancel.addActionListener { dispose() }
    add.addActionListener {
      try {
        owner.modelServices.filters.create(Filter(nameField.text, filter.text))
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
