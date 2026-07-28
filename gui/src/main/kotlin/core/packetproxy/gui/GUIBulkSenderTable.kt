package packetproxy.gui

import java.util.function.Consumer
import javax.swing.*
import packetproxy.model.OneShotPacket
import packetproxy.model.OptionTableModel
import packetproxy.model.PacketSummarizer
import packetproxy.model.RegexParam

class GUIBulkSenderTable(
  private var type: Type,
  private var packetSummarizer: PacketSummarizer,
  private var onSelected: Consumer<Int>,
) {
  enum class Type {
    CLIENT,
    SERVER,
  }

  private lateinit var model: OptionTableModel
  private lateinit var table: JTable
  private var regexParams = mutableListOf<RegexParam>()

  fun createPanel(): JComponent {
    var names =
      if (type == Type.CLIENT) arrayOf("#", "Client Request") else arrayOf("#", "Server Response")
    model =
      object : OptionTableModel(names, 0) {
        override fun isCellEditable(row: Int, column: Int) = false
      }
    table =
      JTable(model).apply {
        autoCreateRowSorter = true
        apply(this, names.size)
      }
    table.selectionModel.addListSelectionListener { onSelected.accept(selectedPacketId) }
    return JScrollPane(table)
  }

  val selectedPacketId: Int
    get() =
      if (table.selectedRow in 0 until table.rowCount) table.getValueAt(table.selectedRow, 0) as Int
      else 0

  fun add(packet: OneShotPacket) {
    model.addRow(
      arrayOf(
        packet.getId(),
        if (type == Type.CLIENT) packet.getSummarizedRequest(packetSummarizer)
        else packet.getSummarizedResponse(packetSummarizer),
      )
    )
  }

  fun clear() {
    model.rowCount = 0
    regexParams.clear()
  }

  fun getRegexParams(): List<RegexParam> = regexParams
}
