package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.beans.PropertyChangeEvent
import packetproxy.common.i18nStringArray
import packetproxy.model.PropertyChangeEventType.SSL_PASS_THROUGHS
import packetproxy.model.SSLPassThrough
import packetproxy.util.errWithStackTrace

class GUIOptionSSLPassThrough(owner: GUIMain) : GUIOptionComponentBase<SSLPassThrough>(owner) {
  private val sslPassThroughs = owner.modelServices.sslPassThroughs
  private val tableList = mutableListOf<SSLPassThrough>()

  init {
    sslPassThroughs.addPropertyChangeListener(this)
    val tableAction =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val columnIndex = table.columnAtPoint(e.point)
            val rowIndex = table.rowAtPoint(e.point)
            if (columnIndex == 0) {
              val sslPassThrough = getTableContent(rowIndex)
              if (table.getValueAt(rowIndex, 0) as Boolean) sslPassThrough.setDisabled()
              else sslPassThrough.setEnabled()
              sslPassThroughs.update(sslPassThrough)
            }
            table.setRowSelectionInterval(rowIndex, rowIndex)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    jcomponent =
      createComponent(
        i18nStringArray("Enabled", "Server Name", "Applied Listen Port"),
        intArrayOf(80, 570, 150),
        tableAction,
        {
          try {
            val sslPassThrough = GUIOptionSSLPassThroughDialog(owner).showDialog()
            if (sslPassThrough != null) {
              sslPassThrough.setEnabled()
              sslPassThroughs.create(sslPassThrough)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
        {
          try {
            val oldSslPassThrough = getSelectedTableContent()
            val sslPassThrough = GUIOptionSSLPassThroughDialog(owner).showDialog(oldSslPassThrough)
            if (sslPassThrough != null) {
              sslPassThroughs.delete(oldSslPassThrough)
              sslPassThrough.setEnabled()
              sslPassThroughs.create(sslPassThrough)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
        {
          try {
            sslPassThroughs.delete(getSelectedTableContent())
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
      )
    updateImpl()
  }

  override fun propertyChange(event: PropertyChangeEvent) {
    if (SSL_PASS_THROUGHS.matches(event)) updateImpl()
  }

  override fun addTableContent(sslPassThrough: SSLPassThrough) {
    tableList.add(sslPassThrough)
    option_model.addRow(
      arrayOf<Any>(
        sslPassThrough.isEnabled(),
        sslPassThrough.getServerName() ?: "",
        if (sslPassThrough.getListenPort() == SSLPassThrough.ALL_PORTS) "*"
        else sslPassThrough.getListenPort(),
      )
    )
  }

  override fun updateTable(sslPassThroughList: List<SSLPassThrough>) {
    clearTableContents()
    sslPassThroughList.forEach(::addTableContent)
  }

  override fun updateImpl() {
    try {
      updateTable(sslPassThroughs.queryAll())
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    tableList.clear()
  }

  override fun getSelectedTableContent(): SSLPassThrough = getTableContent(table.selectedRow)

  override fun getTableContent(rowIndex: Int): SSLPassThrough = tableList[rowIndex]
}
