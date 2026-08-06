package packetproxy.gui

import java.awt.Dimension
import java.awt.EventQueue
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.RowFilter
import javax.swing.table.DefaultTableModel
import javax.swing.table.TableRowSorter
import packetproxy.common.*
import packetproxy.model.CharSet

class GUIOptionCharSetDialog(private val owner: JFrame) : JDialog(owner) {
  private val cancel = JButton(i18nString("Cancel"))
  private val save = JButton(i18nString("Save"))
  private val textCharset = HintTextField(i18nString("(ex.) Shift_JIS"))
  private lateinit var tableModel: CharSetsTableModel
  private lateinit var sorter: TableRowSorter<CharSetsTableModel>
  private var charsets = mutableListOf<CharSet>()

  init {
    title = i18nString("Setting")
    val rect = owner.bounds
    setBounds(rect.x + rect.width / 2 - 250, rect.y + rect.height / 2 - 250, 500, 500)
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(labeled(i18nString("CharSet name:"), textCharset))
    panel.add(createTable())
    panel.add(buttons())
    contentPane.add(panel)
    textCharset.addKeyListener(
      object : java.awt.event.KeyAdapter() {
        override fun keyReleased(e: java.awt.event.KeyEvent) {
          try {
            sorter.rowFilter = RowFilter.regexFilter("(?i)${textCharset.text}", 1)
          } catch (_: Exception) {
            sorter.rowFilter = null
          }
        }
      }
    )
    cancel.addActionListener {
      charsets.clear()
      dispose()
    }
    save.addActionListener {
      charsets = tableModel.checkedValues.toMutableList()
      dispose()
    }
  }

  fun showDialog(): List<CharSet> {
    EventQueue.invokeLater { cancel.requestFocusInWindow() }
    isModal = true
    isVisible = true
    return charsets
  }

  private fun createTable(): JScrollPane {
    val available = owner.modelServices.charSetUtility.getAvailableCharSetList().toSet()
    val data =
      java.nio.charset.Charset.availableCharsets()
        .keys
        .filter { it !in available }
        .map { arrayOf<Any>(false, it) }
        .toTypedArray()
    tableModel = CharSetsTableModel(data, i18nStringArray("", "CharSetName"))
    val table = JTable(tableModel)
    table.columnModel.getColumn(0).minWidth = 50
    table.columnModel.getColumn(0).maxWidth = 50
    table.addMouseListener(
      object : java.awt.event.MouseAdapter() {
        override fun mousePressed(e: java.awt.event.MouseEvent) {
          val row = table.selectedRow
          if (row >= 0 && table.selectedColumn != 0)
            table.setValueAt(!(table.getValueAt(row, 0) as Boolean), row, 0)
        }
      }
    )
    sorter = TableRowSorter(tableModel)
    table.rowSorter = sorter
    return JScrollPane(table)
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
    panel.add(cancel)
    panel.add(save)
    return panel
  }

  private class CharSetsTableModel(data: Array<Array<Any>>, columns: Array<String>) :
    DefaultTableModel(data, columns) {
    override fun isCellEditable(row: Int, column: Int) = column == 0

    override fun getColumnClass(column: Int): Class<*> =
      when (column) {
        0 -> Boolean::class.java
        else -> String::class.java
      }

    val checkedValues: List<CharSet>
      get() =
        (0 until rowCount)
          .filter { getValueAt(it, 0) as? Boolean == true }
          .mapNotNull { getValueAt(it, 1) as? String }
          .map(::CharSet)
  }
}
