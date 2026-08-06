package packetproxy.gui

import javax.swing.*
import javax.swing.table.TableRowSorter
import packetproxy.common.i18nString
import packetproxy.common.i18nStringArray
import packetproxy.model.OptionTableModel
import packetproxy.model.RegexParam
import packetproxy.util.errWithStackTrace

class GUIRegexParamsTableDialog(
  private var owner: JFrame,
  private var regexParams: MutableList<RegexParam>,
  private var basePacketId: Int,
) : JDialog(owner) {
  private lateinit var model: OptionTableModel
  private lateinit var table: JTable

  init {
    title = i18nString("regex params")
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
    regexParams.forEach {
      model.addRow(arrayOf<Any?>(it.getPacketId(), it.getName(), it.getRegex()))
    }
  }

  fun createPanel(): JComponent {
    var names = i18nStringArray("Base Packet ID", "Param Name", "Regex to pickup")
    model =
      object : OptionTableModel(names, 0) {
        override fun isCellEditable(row: Int, column: Int) = false
      }
    table =
      JTable(model).apply {
        rowSorter = TableRowSorter(model)
        rowHeight = owner.modelServices.fontManager.getUIFontHeight(this)
      }
    var buttons = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
    buttons.add(
      JButton(i18nString("Add")).apply {
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
      JButton(i18nString("Remove")).apply {
        addActionListener {
          if (table.selectedRow < 0) {
            return@addActionListener
          }
          regexParams.removeAt(table.convertRowIndexToModel(table.selectedRow))
          updateTable()
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
