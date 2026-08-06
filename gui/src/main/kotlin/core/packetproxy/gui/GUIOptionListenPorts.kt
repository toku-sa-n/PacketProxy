package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import packetproxy.common.i18nStringArray
import packetproxy.model.ListenPort
import packetproxy.util.errWithStackTrace

class GUIOptionListenPorts(owner: GUIMain) : GUIOptionComponentBase<ListenPort>(owner) {
  private val listenPorts = owner.modelServices.listenPorts
  private val values = mutableListOf<ListenPort>()

  init {
    listenPorts.addPropertyChangeListener(this)
    owner.modelServices.servers.addPropertyChangeListener(this)
    val action =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val row = table.rowAtPoint(e.point)
            if (row < 0) return
            table.setRowSelectionInterval(row, row)
            if (table.columnAtPoint(e.point) == 0) {
              val port = getSelectedTableContent() ?: return
              if (table.getValueAt(row, 0) as Boolean) port.setDisabled() else port.setEnabled()
              listenPorts.update(port)
            }
          } catch (ex: Exception) {
            errWithStackTrace(ex)
          }
        }
      }
    jcomponent =
      createComponent(
        i18nStringArray("Enabled", "Protocol", "Listen Port", "Port Type", "CA", "Forward Server"),
        intArrayOf(50, 50, 80, 120, 250, 300),
        action,
        {
          try {
            GUIOptionListenPortDialog(owner).showDialog()?.let {
              it.setEnabled()
              listenPorts.create(it)
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            val old = getSelectedTableContent() ?: return@createComponent
            GUIOptionListenPortDialog(owner).showDialog(old)?.let {
              listenPorts.delete(old)
              it.setEnabled()
              listenPorts.create(it)
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            getSelectedTableContent()?.let { listenPorts.delete(it) }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
      )
    updateImpl()
  }

  fun dispose() {
    listenPorts.removePropertyChangeListener(this)
    owner.modelServices.servers.removePropertyChangeListener(this)
  }

  override fun addTableContent(value: ListenPort) {
    values.add(value)
    val serverNull = if (value.getType()!!.isForwarder()) "Deleted" else ""
    option_model.addRow(
      arrayOf(
        value.isEnabled(),
        value.getProtocol(),
        value.getPort(),
        value.getType(),
        value.getCA().map { it.getName() }.orElse("Error"),
        value.getServer(owner.modelServices.database)?.toString() ?: serverNull,
      )
    )
  }

  override fun updateTable(values: List<ListenPort>) {
    clearTableContents()
    for (value in values) addTableContent(value)
  }

  override fun updateImpl() {
    try {
      updateTable(listenPorts.queryAll())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    this.values.clear()
  }

  override fun getSelectedTableContent(): ListenPort? {
    val rowIndex = selectedModelRowOrNull() ?: return null
    return getTableContent(rowIndex)
  }

  override fun getTableContent(rowIndex: Int) = values[rowIndex]
}
