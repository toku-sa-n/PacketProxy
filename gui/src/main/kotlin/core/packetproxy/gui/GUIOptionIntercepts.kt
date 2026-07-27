package packetproxy.gui

import java.awt.event.MouseAdapter
import javax.swing.JFrame
import packetproxy.model.InterceptOption
import packetproxy.model.InterceptOptions
import packetproxy.util.Logging.errWithStackTrace

class GUIOptionIntercepts(owner: JFrame) : GUIOptionComponentBase<InterceptOption>(owner) {
  private val interceptOptions = InterceptOptions.getInstance()
  private val tableList = mutableListOf<InterceptOption>()

  init {
    interceptOptions.addPropertyChangeListener(this)
    jcomponent =
      createComponent(
        arrayOf("Enabled", "Direction", "Action and Condition", "Type", "Pattern", "Target Server"),
        intArrayOf(50, 160, 300, 50, 80, 90),
        object : MouseAdapter() {},
        {
          try {
            GUIOptionInterceptDialog(owner).showDialog()?.let(interceptOptions::create)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            val old = getSelectedTableContent()
            GUIOptionInterceptDialog(owner).showDialog(old)?.let {
              it.setId(old.getId())
              interceptOptions.update(it)
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            interceptOptions.delete(getSelectedTableContent())
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
      )
    updateImpl()
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
        value.getServerName(),
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

  override fun getSelectedTableContent() = getTableContent(table.selectedRow)

  override fun getTableContent(rowIndex: Int) = tableList[rowIndex]
}
