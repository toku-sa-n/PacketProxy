package packetproxy.gui

import java.awt.*
import javax.swing.*
import javax.swing.table.DefaultTableModel
import packetproxy.common.*
import packetproxy.model.Filter
import packetproxy.util.errWithStackTrace

class GUIFilterConfig(private var owner: JFrame) {
  private var model =
    ProjectTableModel(arrayOf("#", i18nString("Filter name"), i18nString("Filter")), 0)
  private var table = JTable(model)

  init {
    updateImpl()
  }

  inner class ProjectTableModel(columns: Array<String>, rows: Int) :
    DefaultTableModel(columns, rows) {
    override fun getColumnClass(column: Int): Class<*> = getValueAt(0, column).javaClass
  }

  fun createPanel(): JComponent {
    table.apply {
      getColumnModel().getColumn(0).minWidth = 40
      getColumnModel().getColumn(0).maxWidth = 40
      getColumn("#").preferredWidth = 40
      getColumn(i18nString("Filter name")).preferredWidth = 150
      getColumn(i18nString("Filter")).preferredWidth = 610
    }
    var buttons = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
    listOf("Add", "Edit", "Remove").forEach { title ->
      buttons.add(JButton(title).apply { addActionListener { handle(title) } })
    }
    return JPanel().apply {
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(buttons)
      add(JScrollPane(table).apply { background = Color.WHITE })
    }
  }

  private fun handle(action: String) {
    try {
      when (action) {
        "Add" -> GUIFilterConfigAddDialog(owner).showDialog()
        "Edit" -> GUIFilterConfigEditDialog(owner, selected()).showDialog()
        "Remove" ->
          if (
            JOptionPane.showConfirmDialog(
              owner,
              String.format(
                i18nString("Are you sure you want to delete %s ?"),
                selected().getName(),
              ),
              i18nString("Delete filter"),
              JOptionPane.OK_CANCEL_OPTION,
              JOptionPane.WARNING_MESSAGE,
            ) == JOptionPane.YES_OPTION
          )
            owner.modelServices.filters.delete(selected())
      }
      updateImpl()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun updateImpl() {
    model.rowCount = 0
    owner.modelServices.filters.queryAll().forEach {
      model.addRow(arrayOf(it.getId(), it.getName(), it.getFilter()))
    }
  }

  private fun selected(): Filter =
    requireNotNull(owner.modelServices.filters.query(table.getValueAt(table.selectedRow, 0) as Int))
}
