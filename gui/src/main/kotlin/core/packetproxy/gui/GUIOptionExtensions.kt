package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import packetproxy.common.i18nStringArray
import packetproxy.model.Extension
import packetproxy.util.errWithStackTrace

class GUIOptionExtensions(owner: GUIMain) : GUIOptionComponentBase<Extension>(owner) {
  private val extensions = owner.modelServices.extensions
  private val extensionList = mutableListOf<Extension>()

  init {
    extensions.addPropertyChangeListener(this)
    val action =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val column = table.columnAtPoint(e.point)
            val row = table.rowAtPoint(e.point)
            if (row < 0) return
            table.setRowSelectionInterval(row, row)
            if (column != 0) return
            val enabled = table.getValueAt(row, 0) as Boolean
            val extension = getSelectedTableContent() ?: return
            extension.setEnabled(!enabled)
            val updated = extensions.update(extension)
            if (!enabled && updated != null) owner.getGuiExtensions().addExtension(updated)
            else if (enabled) owner.getGuiExtensions().removeExtension(extension)
          } catch (ex: Exception) {
            errWithStackTrace(ex)
          }
        }
      }
    jcomponent =
      createComponent(
        i18nStringArray("Enabled", "Name", "Path"),
        intArrayOf(30, 300, 300),
        action,
        {
          try {
            GUIOptionExtensionsDialog(owner).showDialog()?.let { extensions.create(it) }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            val old = getSelectedTableContent() ?: return@createComponent
            val updated = GUIOptionExtensionsDialog(owner).showDialog(old)
            if (
              updated != null &&
                (updated.getName() != old.getName() || updated.getPath() != old.getPath())
            ) {
              owner.getGuiExtensions().removeExtension(old)
              extensions.delete(old)
              extensions.create(updated)
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
        {
          try {
            val extension = getSelectedTableContent() ?: return@createComponent
            owner.getGuiExtensions().removeExtension(extension)
            extensions.delete(extension)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        },
      )
    updateImpl()
  }

  fun dispose() {
    extensions.removePropertyChangeListener(this)
  }

  override fun addTableContent(value: Extension) {
    extensionList.add(value)
    option_model.addRow(arrayOf(value.isEnabled(), value.getName(), value.getPath()))
  }

  override fun updateTable(values: List<Extension>) {
    clearTableContents()
    for (value in values) addTableContent(value)
  }

  override fun updateImpl() {
    try {
      updateTable(extensions.queryAll())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    extensionList.clear()
  }

  override fun getSelectedTableContent(): Extension? {
    val rowIndex = selectedModelRowOrNull() ?: return null
    return getTableContent(rowIndex)
  }

  override fun getTableContent(rowIndex: Int) = extensionList[rowIndex]
}
