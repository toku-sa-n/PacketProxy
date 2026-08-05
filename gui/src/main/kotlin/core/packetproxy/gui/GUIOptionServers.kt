package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import packetproxy.common.i18nStringArray
import packetproxy.model.Server
import packetproxy.util.errWithStackTrace

class GUIOptionServers(owner: GUIMain) : GUIOptionComponentBase<Server>(owner) {
  private val servers = owner.modelServices.servers
  private val values = mutableListOf<Server>()

  init {
    servers.addPropertyChangeListener(this)
    val action =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val row = table.rowAtPoint(e.point)
            if (row < 0) return
            table.setRowSelectionInterval(row, row)
            val server = getSelectedTableContent()
            when (table.columnAtPoint(e.point)) {
              4 ->
                if (table.getValueAt(row, 4) as Boolean) server.disableResolved()
                else server.enableResolved()
              5 ->
                if (table.getValueAt(row, 5) as Boolean) server.disableResolved6()
                else server.enableResolved6()
              else -> return
            }
            servers.update(server)
          } catch (ex: Exception) {
            errWithStackTrace(ex)
          }
        }
      }
    jcomponent =
      createComponentForServers(
        i18nStringArray(
          "Host",
          "Port",
          "Use SSL",
          "Encode Module",
          "Spoof DNS(A)",
          "Spoof DNS(AAAA)",
          "HttpProxy",
          "Comment",
        ),
        intArrayOf(200, 80, 50, 160, 60, 60, 60, 100),
        action,
        {
          try {
            GUIOptionServerDialog(owner).showDialog()?.let { servers.create(it) }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            GUIOptionServerDialog(owner).showDialog(getSelectedTableContent())?.let {
              servers.update(it)
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            servers.delete(getSelectedTableContent())
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
      )
    updateImpl()
  }

  override fun addTableContent(value: Server) {
    values.add(value)
    option_model.addRow(
      arrayOf(
        value.getIp(),
        value.getPort(),
        value.getUseSSL(),
        value.getEncoder(),
        value.isResolved(),
        value.isResolved6(),
        value.isHttpProxy(),
        value.getComment(),
      )
    )
  }

  override fun updateTable(values: List<Server>) {
    clearTableContents()
    for (value in values) addTableContent(value)
  }

  override fun updateImpl() {
    try {
      updateTable(servers.queryAll())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun clearTableContents() {
    values.clear()
    option_model.rowCount = 0
  }

  override fun getSelectedTableContent() =
    getTableContent(table.rowSorter.convertRowIndexToModel(table.selectedRow))

  override fun getTableContent(rowIndex: Int) = values[rowIndex]
}
