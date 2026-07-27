package packetproxy.gui

import java.util.function.Consumer
import javax.swing.*
import javax.swing.table.DefaultTableModel
import packetproxy.common.I18nString
import packetproxy.model.Filter
import packetproxy.model.Filters
import packetproxy.util.Logging.err
import packetproxy.util.Logging.errWithStackTrace

class GUIFilterDropDownList(owner: JFrame, width: Int, private var consumer: Consumer<Filter>) :
  JDialog(owner) {
  private var table: JTable

  init {
    isUndecorated = true
    var model =
      object : DefaultTableModel(arrayOf("filter name", "filter"), 0) {
        override fun isCellEditable(row: Int, column: Int) = false
      }
    table =
      JTable(model).apply {
        tableHeader = null
        getColumnModel().getColumn(0).preferredWidth = 150
        getColumnModel().getColumn(1).preferredWidth = width - 150
      }
    var defaults =
      listOf(
        Filter(
          I18nString.get("No image,css,js,font"),
          "type != image && type != css && type != javascript && type != font",
        )
      )
    (Filters.getInstance().queryAll() + defaults).forEach {
      model.addRow(arrayOf(it.getName(), it.getFilter()))
    }
    table.addMouseListener(
      object : java.awt.event.MouseAdapter() {
        override fun mouseReleased(e: java.awt.event.MouseEvent) {
          try {
            var row = table.selectedRow
            if (row in 0 until table.rowCount)
              consumer.accept(
                Filter(table.getValueAt(row, 0) as String, table.getValueAt(row, 1) as String)
              )
            else err(row.toString())
          } catch (x: Exception) {
            errWithStackTrace(x)
          }
        }
      }
    )
    contentPane.add(table)
  }

  fun showDialog(): Int {
    isVisible = true
    return table.height
  }
}
