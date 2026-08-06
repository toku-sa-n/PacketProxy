package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JOptionPane
import packetproxy.common.i18nString
import packetproxy.common.i18nStringArray
import packetproxy.model.InterceptOption
import packetproxy.model.InterceptOption.Direction
import packetproxy.util.errWithStackTrace

class GUIOptionIntercepts(owner: GUIMain) : GUIOptionComponentBase<InterceptOption>(owner) {
  private val interceptOptions = owner.modelServices.interceptOptions
  private val tableList = mutableListOf<InterceptOption>()

  init {
    interceptOptions.addPropertyChangeListener(this)
    val tableAction =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val columnIndex = table.columnAtPoint(e.point)
            val rowIndex = table.rowAtPoint(e.point)
            if (columnIndex == 0) {
              val enableCheckbox = table.getValueAt(rowIndex, 0) as Boolean
              val intercept = getTableContent(rowIndex)
              if (enableCheckbox) {
                if (
                  intercept.isDirection(Direction.ALL_THE_OTHER_REQUESTS) ||
                    intercept.isDirection(Direction.ALL_THE_OTHER_RESPONSES)
                ) {
                  JOptionPane.showMessageDialog(owner, i18nString("This entry can't be disabled."))
                } else {
                  intercept.setDisabled()
                }
              } else {
                intercept.setEnabled()
              }
              interceptOptions.update(intercept)
            }
            table.setRowSelectionInterval(rowIndex, rowIndex)
          } catch (e1: Exception) {
            errWithStackTrace(e1)
          }
        }
      }
    jcomponent =
      createComponent(
        i18nStringArray(
          "Enabled",
          "Direction",
          "Action and Condition",
          "Type",
          "Pattern",
          "Target Server",
        ),
        intArrayOf(50, 160, 300, 50, 80, 90),
        tableAction,
        {
          try {
            GUIOptionInterceptDialog(owner).showDialog()?.let(interceptOptions::create)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            val old = getSelectedTableContent() ?: return@createComponent
            val updated =
              if (
                old.isDirection(Direction.ALL_THE_OTHER_REQUESTS) ||
                  old.isDirection(Direction.ALL_THE_OTHER_RESPONSES)
              ) {
                GUIOptionInterceptEditOthersDialog(owner).showDialog(old)
              } else {
                GUIOptionInterceptDialog(owner).showDialog(old)
              }
            updated?.let {
              it.setId(old.getId())
              interceptOptions.update(it)
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            val intercept = getSelectedTableContent() ?: return@createComponent
            if (
              intercept.isDirection(Direction.ALL_THE_OTHER_REQUESTS) ||
                intercept.isDirection(Direction.ALL_THE_OTHER_RESPONSES)
            ) {
              JOptionPane.showMessageDialog(owner, i18nString("This entry can't be removed."))
              return@createComponent
            }
            interceptOptions.delete(intercept)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
      )
    updateImpl()
  }

  fun dispose() {
    interceptOptions.removePropertyChangeListener(this)
  }

  override fun addTableContent(value: InterceptOption) {
    tableList.add(value)
    option_model.addRow(
      arrayOf<Any?>(
        value.isEnabled(),
        value.getDirectionAsString(),
        value.getRelationshipAsString(),
        value.getMethodAsString(),
        value.getPattern(),
        value.getServerName(owner.modelServices.database),
      )
    )
  }

  override fun updateTable(values: List<InterceptOption>) {
    clearTableContents()
    values.forEach(::addTableContent)
  }

  override fun updateImpl() {
    try {
      updateTable(interceptOptions.queryAll())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    tableList.clear()
  }

  override fun getSelectedTableContent(): InterceptOption? {
    val rowIndex = selectedModelRowOrNull() ?: return null
    return getTableContent(rowIndex)
  }

  override fun getTableContent(rowIndex: Int) = tableList[rowIndex]
}
