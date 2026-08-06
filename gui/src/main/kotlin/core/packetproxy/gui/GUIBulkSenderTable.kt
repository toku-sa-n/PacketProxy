package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.util.function.Consumer
import javax.swing.*
import packetproxy.common.Utils
import packetproxy.common.i18nString
import packetproxy.common.i18nStringArray
import packetproxy.model.OneShotPacket
import packetproxy.model.OptionTableModel
import packetproxy.model.PacketSummarizer
import packetproxy.model.RegexParam
import packetproxy.util.errWithStackTrace

class GUIBulkSenderTable(
  private var owner: JFrame,
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
  private var onDeleteRequested: Runnable? = null

  /** 右クリックメニューからの削除要求を受け取るハンドラを登録する */
  fun setOnDeleteRequested(handler: Runnable) {
    onDeleteRequested = handler
  }

  fun createPanel(): JComponent {
    var names =
      if (type == Type.CLIENT) i18nStringArray("#", "Client Request", "Status")
      else i18nStringArray("#", "Server Response")
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
    if (type == Type.CLIENT) {
      addRegexParamsMenu()
    }
    return JScrollPane(table)
  }

  val selectedPacketId: Int
    get() =
      if (table.selectedRow in 0 until table.rowCount) table.getValueAt(table.selectedRow, 0) as Int
      else 0

  /** 選択されている全行のパケットIDを返す */
  fun getSelectedPacketIds(): List<Int> =
    table.selectedRows
      .filter { it in 0 until table.rowCount }
      .map { table.getValueAt(it, 0) as Int }

  /** 選択されている行を削除し、削除したパケットIDを返す */
  fun deleteSelectedRows(): List<Int> {
    var ids = getSelectedPacketIds()
    if (ids.isEmpty()) {
      return ids
    }
    // 削除で行番号がずれないよう、モデル上の行を降順に消す
    table.selectedRows
      .map { table.convertRowIndexToModel(it) }
      .sortedDescending()
      .forEach { model.removeRow(it) }
    regexParams.removeAll { it.getPacketId() in ids }
    return ids
  }

  /** 選択中のパケットを基準にした regex パラメータの編集ダイアログを開く */
  fun showRegexParamsDialog() {
    try {
      GUIRegexParamsTableDialog(owner, regexParams, selectedPacketId).showDialog()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  fun add(packet: OneShotPacket) {
    onEDT {
      if (type == Type.SERVER) {
        model.addRow(arrayOf<Any?>(packet.getId(), packet.getSummarizedResponse(packetSummarizer)))
        return@onEDT
      }
      model.addRow(arrayOf<Any?>(packet.getId(), packet.getSummarizedRequest(packetSummarizer), ""))
    }
  }

  /** 送信状況を Status 列に反映する。Client側テーブルのみが Status 列を持つ */
  fun setStatus(packetId: Int, status: String) {
    if (type != Type.CLIENT) {
      return
    }
    onEDT {
      for (i in 0 until model.rowCount) if (model.getValueAt(i, 0) == packetId) {
        model.setValueAt(status, i, COLUMN_STATUS)
      }
    }
  }

  /** 全行の Status 列を同じ値で埋める */
  fun setStatusForAll(status: String) {
    if (type != Type.CLIENT) {
      return
    }
    onEDT { for (i in 0 until model.rowCount) model.setValueAt(status, i, COLUMN_STATUS) }
  }

  fun clear() {
    onEDT {
      model.rowCount = 0
      regexParams.clear()
    }
  }

  fun getRegexParams(): List<RegexParam> = regexParams

  private fun addRegexParamsMenu() {
    var menu = JPopupMenu()
    menu.add(
      JMenuItem(i18nString("use params")).apply { addActionListener { showRegexParamsDialog() } }
    )
    menu.add(
      JMenuItem(i18nString("delete selected packets")).apply {
        addActionListener { onDeleteRequested?.run() }
      }
    )
    table.addMouseListener(
      object : MouseAdapter() {
        override fun mouseReleased(event: MouseEvent) {
          if (Utils.isWindows() && event.isPopupTrigger) {
            menu.show(event.component, event.x, event.y)
          }
        }

        override fun mousePressed(event: MouseEvent) {
          if (event.isPopupTrigger) {
            menu.show(event.component, event.x, event.y)
          }
        }
      }
    )
  }

  companion object {
    private const val COLUMN_STATUS = 2
  }
}
