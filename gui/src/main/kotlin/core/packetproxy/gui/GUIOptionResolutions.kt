package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import packetproxy.model.Resolution
import packetproxy.util.errWithStackTrace

class GUIOptionResolutions(owner: GUIMain) : GUIOptionComponentBase<Resolution>(owner) {
  private val resolutions = owner.modelServices.resolutions
  private val tableList = mutableListOf<Resolution>()

  init {
    resolutions.addPropertyChangeListener(this)
    val tableAction =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val columnIndex = table.columnAtPoint(e.point)
            val rowIndex = table.rowAtPoint(e.point)
            if (columnIndex == 2) {
              val resolution = getTableContent(rowIndex)
              if (table.getValueAt(rowIndex, 2) as Boolean) resolution.disableResolution()
              else resolution.enableResolution()
              resolutions.update(resolution)
            }
            table.setRowSelectionInterval(rowIndex, rowIndex)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    jcomponent =
      createComponent(
        arrayOf("IP Addr", "Host", "Override", "Comment"),
        intArrayOf(200, 200, 50, 100),
        tableAction,
        {
          try {
            resolutions.create(GUIOptionResolutionDialog(owner).showDialog())
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
        {
          try {
            val oldResolution = getSelectedTableContent()
            val resolution = GUIOptionResolutionDialog(owner).showDialog(oldResolution)
            if (resolution != null) {
              resolutions.delete(oldResolution)
              resolutions.create(resolution)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
        {
          try {
            resolutions.delete(getSelectedTableContent())
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
      )
    updateImpl()
  }

  override fun addTableContent(resolution: Resolution) {
    tableList.add(resolution)
    option_model.addRow(
      arrayOf<Any>(
        resolution.getIp() ?: "",
        resolution.getHostName() ?: "",
        resolution.isEnabled(),
        resolution.getComment() ?: "",
      )
    )
  }

  override fun updateTable(resolutionList: List<Resolution>) {
    clearTableContents()
    resolutionList.forEach(::addTableContent)
  }

  override fun updateImpl() {
    try {
      updateTable(resolutions.queryAll())
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    tableList.clear()
  }

  override fun getSelectedTableContent(): Resolution = getTableContent(table.selectedRow)

  override fun getTableContent(rowIndex: Int): Resolution = tableList[rowIndex]
}
