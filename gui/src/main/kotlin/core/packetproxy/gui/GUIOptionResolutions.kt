package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import packetproxy.common.i18nStringArray
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
        i18nStringArray("IP Addr", "Host", "Override", "Comment"),
        intArrayOf(200, 200, 50, 100),
        tableAction,
        {
          try {
            GUIOptionResolutionDialog(owner).showDialog()?.let { resolutions.create(it) }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
        {
          try {
            val oldResolution = getSelectedTableContent() ?: return@createComponent
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
            getSelectedTableContent()?.let { resolutions.delete(it) }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
      )
    updateImpl()
  }

  fun dispose() {
    resolutions.removePropertyChangeListener(this)
  }

  override fun addTableContent(value: Resolution) {
    tableList.add(value)
    option_model.addRow(
      arrayOf<Any?>(
        value.getIp() ?: "",
        value.getHostName() ?: "",
        value.isEnabled(),
        value.getComment() ?: "",
      )
    )
  }

  override fun updateTable(values: List<Resolution>) {
    clearTableContents()
    values.forEach(::addTableContent)
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

  override fun getSelectedTableContent(): Resolution? {
    val rowIndex = selectedModelRowOrNull() ?: return null
    return getTableContent(rowIndex)
  }

  override fun getTableContent(rowIndex: Int): Resolution = tableList[rowIndex]
}
