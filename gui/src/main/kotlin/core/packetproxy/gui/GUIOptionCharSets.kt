package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JFrame
import packetproxy.model.CharSet
import packetproxy.model.CharSets
import packetproxy.util.Logging.errWithStackTrace

class GUIOptionCharSets(owner: JFrame) : GUIOptionComponentBase<CharSet>(owner) {
  private val charsets = CharSets.getInstance()
  private val charsetList = mutableListOf<CharSet>()

  init {
    charsets.addPropertyChangeListener(this)
    val action =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val row = table.rowAtPoint(e.point)
            if (row < 0) return
            table.setRowSelectionInterval(row, row)
          } catch (ex: Exception) {
            errWithStackTrace(ex)
          }
        }
      }
    jcomponent =
      createComponent(
        arrayOf("CharSetName"),
        intArrayOf(200, 80, 50, 160, 60, 60, 100),
        action,
        {
          try {
            for (charset in GUIOptionCharSetDialog(owner).showDialog()) charsets.create(charset)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        null,
        {
          try {
            charsets.delete(getSelectedTableContent())
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
      )
    updateImpl()
  }

  override fun addTableContent(value: CharSet) {
    charsetList.add(value)
    option_model.addRow(arrayOf(value.getCharSetName()))
  }

  override fun updateTable(values: List<CharSet>) {
    clearTableContents()
    for (value in values) addTableContent(value)
  }

  override fun updateImpl() {
    try {
      updateTable(charsets.queryAll())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun clearTableContents() {
    charsetList.clear()
    option_model.rowCount = 0
  }

  override fun getSelectedTableContent() = getTableContent(table.selectedRow)

  override fun getTableContent(rowIndex: Int) = charsetList[rowIndex]
}
