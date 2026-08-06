package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import packetproxy.common.i18nStringArray
import packetproxy.model.Modification
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class GUIOptionModifications(owner: GUIMain) : GUIOptionComponentBase<Modification>(owner) {
  private val modifications = owner.modelServices.modifications
  private val tableList = mutableListOf<Modification>()

  init {
    modifications.addPropertyChangeListener(this)
    val tableAction =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val columnIndex = table.columnAtPoint(e.point)
            val rowIndex = table.rowAtPoint(e.point)
            if (columnIndex == 0) {
              val modification = getTableContent(rowIndex)
              if (table.getValueAt(rowIndex, 0) as Boolean) modification.setDisabled()
              else modification.setEnabled()
              modifications.update(modification)
            }
            table.setRowSelectionInterval(rowIndex, rowIndex)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    jcomponent =
      createComponent(
        i18nStringArray(
          "Enabled",
          "Type",
          "Method",
          "Pattern",
          "Replaced",
          "Path",
          "Applied Server",
        ),
        intArrayOf(50, 100, 50, 150, 150, 120, 130),
        tableAction,
        {
          try {
            val modification = GUIOptionModificationDialog(owner).showDialog()
            if (modification != null) {
              modification.setEnabled()
              modifications.create(modification)
            }
            log("Modification button is pressed.")
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
        {
          try {
            val oldModification = getSelectedTableContent() ?: return@createComponent
            val modification = GUIOptionModificationDialog(owner).showDialog(oldModification)
            if (modification != null) {
              modifications.delete(oldModification)
              modification.setEnabled()
              modifications.create(modification)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
        {
          try {
            getSelectedTableContent()?.let { modifications.delete(it) }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
      )
    updateImpl()
  }

  fun dispose() {
    modifications.removePropertyChangeListener(this)
  }

  override fun addTableContent(modification: Modification) {
    tableList.add(modification)
    option_model.addRow(
      arrayOf<Any?>(
        modification.isEnabled(),
        modification.getDirection(),
        modification.getMethod(),
        modification.getPattern(),
        modification.getReplaced(),
        modification.getPath(),
        modification.getServerName(owner.modelServices.database),
      )
    )
  }

  override fun updateTable(modificationList: List<Modification>) {
    clearTableContents()
    modificationList.forEach(::addTableContent)
  }

  override fun updateImpl() {
    try {
      updateTable(modifications.queryAll())
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    tableList.clear()
  }

  override fun getSelectedTableContent(): Modification? {
    val rowIndex = selectedModelRowOrNull() ?: return null
    return getTableContent(rowIndex)
  }

  override fun getTableContent(rowIndex: Int): Modification = tableList[rowIndex]
}
