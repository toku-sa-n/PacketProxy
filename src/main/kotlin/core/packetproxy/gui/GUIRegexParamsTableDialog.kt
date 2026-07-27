package packetproxy.gui

import javax.swing.*
import javax.swing.table.TableRowSorter
import packetproxy.common.FontManager
import packetproxy.model.OptionTableModel
import packetproxy.model.RegexParam
import packetproxy.util.Logging.errWithStackTrace

class GUIRegexParamsTableDialog(
  private var owner: JFrame,
  private var regexParams: MutableList<RegexParam>,
  private var basePacketId: Int,
) : JDialog(owner) {
  private lateinit var model: OptionTableModel
  private lateinit var table: JTable

  init {
    title = "regex params"
    contentPane.add(createPanel())
    var r = owner.bounds
    setBounds(r.x + 50, r.y + r.height / 2 - 150, r.width - 100, 300)
  }

  fun showDialog(): List<RegexParam> {
    updateTable()
    isModal = true
    isVisible = true
    return regexParams
  }

  fun updateTable() {
    model.rowCount = 0
    regexParams.forEach { model.addRow(arrayOf(it.getPacketId(), it.getName(), it.getRegex())) }
  }

  fun createPanel(): JComponent {
    var names = arrayOf("Base Packet ID", "Param Name", "Regex to pickup")
    model =
      object : OptionTableModel(names, 0) {
        override fun isCellEditable(row: Int, column: Int) = false
      }
    table =
      JTable(model).apply {
        rowSorter = TableRowSorter(model)
        rowHeight = FontManager.getInstance().getUIFontHeight(this)
      }
    var buttons = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
    buttons.add(
      JButton("Add").apply {
        addActionListener {
          try {
            GUIRegexParamDialog(owner).showDialog(RegexParam(basePacketId, "", ""))?.let {
              regexParams.add(it)
            }
            updateTable()
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    )
    buttons.add(
      JButton("Remove").apply {
        addActionListener {
          if (table.selectedRow >= 0) {
            regexParams.removeAt(table.selectedRow)
            updateTable()
          }
        }
      }
    )
    return JPanel().apply {
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(buttons)
      add(CustomScrollPane().apply { viewport.view = table })
    }
  }
}
