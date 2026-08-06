package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import packetproxy.common.i18nStringArray
import packetproxy.model.CharSet
import packetproxy.util.errWithStackTrace

class GUIOptionCharSets(owner: GUIMain) : GUIOptionComponentBase<CharSet>(owner) {
  private val charsets = owner.modelServices.charSets
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
        i18nStringArray("CharSetName"),
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
            getSelectedTableContent()?.let { charsets.delete(it) }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
      )
    updateImpl()
  }

  fun dispose() {
    charsets.removePropertyChangeListener(this)
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

  override fun getSelectedTableContent(): CharSet? {
    val rowIndex = selectedModelRowOrNull() ?: return null
    return getTableContent(rowIndex)
  }

  override fun getTableContent(rowIndex: Int) = charsetList[rowIndex]
}
