package packetproxy.gui

import java.util.function.Consumer
import javax.swing.*
import packetproxy.model.OneShotPacket
import packetproxy.model.OptionTableModel
import packetproxy.model.PacketSummarizer
import packetproxy.util.errWithStackTrace

class GUIVulCheckRecvTable(
  private var packetSummarizer: PacketSummarizer,
  private var onSelected: Consumer<Int>,
) {
  private lateinit var model: OptionTableModel
  private lateinit var table: JTable

  fun createPanel(): JComponent {
    var names = arrayOf("#", "Name", "Server Response", "Length", "Time[msec]", "Encode", "ALPN")
    model =
      object : OptionTableModel(names, 0) {
        override fun isCellEditable(row: Int, column: Int) = false
      }
    table =
      JTable(model).apply {
        autoCreateRowSorter = true
        apply(this, names.size)
      }
    table.selectionModel.addListSelectionListener {
      try {
        onSelected.accept(selectedPacketId)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    return JScrollPane(table)
  }

  val selectedPacketId: Int
    get() =
      if (table.selectedRow in 0 until table.rowCount) table.getValueAt(table.selectedRow, 0) as Int
      else 0

  fun add(id: Int, name: String, packet: OneShotPacket, rtt: Long) {
    model.addRow(
      arrayOf(
        id,
        name,
        packet.getSummarizedResponse(packetSummarizer),
        packet.getData().size,
        rtt,
        packet.getEncoder(),
        packet.getAlpn(),
      )
    )
  }

  fun clear() {
    model.rowCount = 0
  }
}
