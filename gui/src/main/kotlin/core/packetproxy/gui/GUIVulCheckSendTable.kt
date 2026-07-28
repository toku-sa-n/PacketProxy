package packetproxy.gui

import java.util.function.Consumer
import java.util.function.Function
import javax.swing.*
import packetproxy.model.OneShotPacket
import packetproxy.model.OptionTableModel
import packetproxy.util.errWithStackTrace

class GUIVulCheckSendTable(
  private var onSelected: Consumer<String>,
  private var onEnabled: Function<String, Boolean>,
  private var onDisabled: Function<String, Boolean>,
) {
  private lateinit var model: OptionTableModel
  private lateinit var table: JTable

  fun createPanel(): JComponent {
    var names = arrayOf("Enabled", "Name", "Client Request", "Length", "Encode", "ALPN")
    model =
      object : OptionTableModel(names, 0) {
        override fun isCellEditable(row: Int, column: Int) = false
      }
    table =
      JTable(model).apply {
        autoCreateRowSorter = true
        apply(this, names.size)
      }
    table.addMouseListener(
      object : java.awt.event.MouseAdapter() {
        override fun mouseClicked(e: java.awt.event.MouseEvent) {
          try {
            var row = table.rowAtPoint(e.point)
            if (table.columnAtPoint(e.point) == 0) {
              var name = table.getValueAt(row, 1) as String
              var enabled = table.getValueAt(row, 0) as Boolean
              if ((enabled && onDisabled.apply(name)) || (!enabled && onEnabled.apply(name)))
                table.setValueAt(!enabled, row, 0)
            }
            table.setRowSelectionInterval(row, row)
          } catch (x: Exception) {
            errWithStackTrace(x)
          }
        }
      }
    )
    table.selectionModel.addListSelectionListener {
      try {
        onSelected.accept(selectedGeneratorName)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    return JScrollPane(table)
  }

  val selectedGeneratorName: String
    get() =
      if (table.selectedRow in 0 until table.rowCount)
        table.getValueAt(table.selectedRow, 1) as String
      else ""

  fun add(name: String, packet: OneShotPacket, enabled: Boolean) {
    model.addRow(
      arrayOf(
        enabled,
        name,
        packet.getSummarizedRequest(),
        packet.getData().size,
        packet.getEncoder(),
        packet.getAlpn(),
      )
    )
  }

  fun setRow(name: String, packet: OneShotPacket) {
    for (i in 0 until table.rowCount) if (table.getValueAt(i, 1) == name) {
      table.setValueAt(packet.getSummarizedRequest(), i, 2)
      table.setValueAt(packet.getData().size, i, 3)
      table.setValueAt(packet.getEncoder(), i, 4)
      table.setValueAt(packet.getAlpn(), i, 5)
    }
  }

  fun clear() {
    model.rowCount = 0
  }
}
