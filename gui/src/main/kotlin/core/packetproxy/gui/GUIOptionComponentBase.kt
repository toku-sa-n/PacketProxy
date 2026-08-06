/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.gui

import java.awt.Component
import java.awt.Dimension
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTable
import javax.swing.RowFilter
import javax.swing.SwingUtilities
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.TableRowSorter
import packetproxy.common.*
import packetproxy.model.OptionTableModel
import packetproxy.model.PropertyChangeEventType

abstract class GUIOptionComponentBase<T>(protected val owner: GUIMain) : PropertyChangeListener {
  protected lateinit var option_model: OptionTableModel
  protected lateinit var table: JTable
  protected lateinit var jcomponent: JComponent

  fun createPanel(): JComponent {
    jcomponent.alignmentX = Component.LEFT_ALIGNMENT
    return jcomponent
  }

  @Throws(Exception::class)
  protected fun createComponent(
    menu: Array<String>,
    menuWidth: IntArray,
    tableAction: MouseAdapter,
    addAction: ActionListener?,
    editAction: ActionListener?,
    removeAction: ActionListener?,
  ): JComponent {
    option_model =
      object : OptionTableModel(menu, 0) {
        override fun isCellEditable(row: Int, column: Int) = false
      }
    return createTablePanel(
      menu,
      menuWidth,
      tableAction,
      addAction,
      editAction,
      removeAction,
      false,
    )
  }

  @Throws(Exception::class)
  protected fun createComponentForServers(
    menu: Array<String>,
    menuWidth: IntArray,
    tableAction: MouseAdapter,
    addAction: ActionListener?,
    editAction: ActionListener?,
    removeAction: ActionListener?,
  ): JComponent {
    option_model =
      object : OptionTableModel(menu, 0) {
        override fun isCellEditable(row: Int, column: Int) = false
      }
    return createTablePanel(menu, menuWidth, tableAction, addAction, editAction, removeAction, true)
  }

  private fun createTablePanel(
    menu: Array<String>,
    menuWidth: IntArray,
    tableAction: MouseAdapter,
    addAction: ActionListener?,
    editAction: ActionListener?,
    removeAction: ActionListener?,
    searchable: Boolean,
  ): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    table = JTable(option_model)
    for (i in menu.indices) {
      table.getColumn(menu[i]).preferredWidth = menuWidth[i]
    }
    apply(table, menu.size)
    (table.getDefaultRenderer(Boolean::class.java) as JComponent).isOpaque = true
    table.addMouseListener(tableAction)
    if (editAction != null) {
      table.addMouseListener(doubleClickEditListener(editAction))
    }
    table.rowHeight = owner.modelServices.fontManager.getUIFontHeight(table)

    val scrollPane = CustomScrollPane()
    scrollPane.setViewportView(table)
    scrollPane.background = ThemeColors.panelBackground()
    scrollPane.minimumSize = Dimension(TABLE_MINIMUM_WIDTH, TABLE_MINIMUM_HEIGHT)
    scrollPane.preferredSize = Dimension(TABLE_PREFERRED_WIDTH, TABLE_PREFERRED_HEIGHT)
    // ウィンドウの拡大にあわせてテーブルも広がるよう、上限を設けない
    scrollPane.maximumSize = Dimension(Short.MAX_VALUE.toInt(), Short.MAX_VALUE.toInt())
    scrollPane.alignmentY = Component.TOP_ALIGNMENT

    panel.add(createTableButton(addAction, editAction, removeAction))
    if (searchable) {
      val filterText = HintTextField(i18nString("Incremental Search for Host"))
      filterText.minimumSize = Dimension(TABLE_MINIMUM_WIDTH, FILTER_HEIGHT)
      filterText.preferredSize = Dimension(TABLE_PREFERRED_WIDTH, FILTER_HEIGHT)
      filterText.maximumSize = Dimension(Short.MAX_VALUE.toInt(), FILTER_HEIGHT)
      val sorter = TableRowSorter(option_model)
      filterText.document.addDocumentListener(
        object : DocumentListener {
          override fun insertUpdate(e: DocumentEvent) = updateFilter(sorter, filterText.text)

          override fun removeUpdate(e: DocumentEvent) = updateFilter(sorter, filterText.text)

          override fun changedUpdate(e: DocumentEvent) = updateFilter(sorter, filterText.text)
        }
      )
      table.rowSorter = sorter
      val subPanel = JPanel()
      subPanel.layout = BoxLayout(subPanel, BoxLayout.Y_AXIS)
      subPanel.add(scrollPane)
      subPanel.add(filterText)
      subPanel.alignmentY = Component.TOP_ALIGNMENT
      subPanel.background = ThemeColors.panelBackground()
      panel.add(subPanel)
    } else {
      panel.add(scrollPane)
    }
    panel.background = ThemeColors.panelBackground()
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), Short.MAX_VALUE.toInt())
    return panel
  }

  private fun updateFilter(sorter: TableRowSorter<OptionTableModel>, text: String) {
    try {
      sorter.rowFilter = RowFilter.regexFilter(text, 0)
    } catch (_: Exception) {
      sorter.rowFilter = null
    }
  }

  private fun createTableButton(
    addAction: ActionListener?,
    editAction: ActionListener?,
    removeAction: ActionListener?,
  ): JPanel {
    val panel = JPanel()
    val add = JButton(i18nString("Add"))
    val edit = JButton(i18nString("Edit"))
    val remove = JButton(i18nString("Remove"))
    val height = add.minimumSize.height
    for (button in arrayOf(add, edit, remove)) {
      button.maximumSize = Dimension(100, height)
    }
    if (addAction != null) {
      panel.add(add)
      add.addActionListener(addAction)
    }
    if (editAction != null) {
      panel.add(edit)
      edit.addActionListener { event -> runOnSelectedRow(editAction, event, false) }
    }
    if (removeAction != null) {
      panel.add(remove)
      remove.addActionListener { event -> runOnSelectedRow(removeAction, event, true) }
    }
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.background = ThemeColors.panelBackground()
    panel.maximumSize = Dimension(100, panel.minimumSize.height)
    panel.alignmentY = Component.TOP_ALIGNMENT
    return panel
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (!shouldHandlePropertyChange(evt)) return
    SwingUtilities.invokeLater { updateImpl() }
  }

  /** Subclasses may override to filter which property-change events refresh the table. */
  protected open fun shouldHandlePropertyChange(evt: PropertyChangeEvent): Boolean =
    enumValues<PropertyChangeEventType>().any { it.matches(evt) }

  protected fun selectedModelRowOrNull(): Int? {
    val selectedRow = table.selectedRow
    if (selectedRow < 0) return null
    val sorter = table.rowSorter
    return if (sorter != null) sorter.convertRowIndexToModel(selectedRow) else selectedRow
  }

  protected abstract fun clearTableContents()

  protected abstract fun getTableContent(rowIndex: Int): T

  protected abstract fun getSelectedTableContent(): T?

  protected abstract fun addTableContent(value: T)

  protected abstract fun updateTable(values: List<T>)

  protected abstract fun updateImpl()

  /** 行が選択されていない場合は案内を表示し、削除の場合は確認を取ってから実行する。 */
  private fun runOnSelectedRow(
    action: ActionListener,
    event: ActionEvent,
    needsConfirmation: Boolean,
  ) {
    if (table.selectedRow < 0) {
      JOptionPane.showMessageDialog(
        owner,
        i18nString("Select a row first."),
        i18nString("Message"),
        JOptionPane.INFORMATION_MESSAGE,
      )
      return
    }
    if (needsConfirmation && !confirmRemoval()) {
      return
    }
    action.actionPerformed(event)
  }

  private fun confirmRemoval(): Boolean =
    JOptionPane.showConfirmDialog(
      owner,
      i18nString("Are you sure you want to remove the selected entry?"),
      i18nString("Confirmation"),
      JOptionPane.YES_NO_OPTION,
      JOptionPane.WARNING_MESSAGE,
    ) == JOptionPane.YES_OPTION

  /** 行のダブルクリックで編集ダイアログを開く。チェックボックス列は有効/無効の切り替えなので対象外。 */
  private fun doubleClickEditListener(editAction: ActionListener): MouseAdapter =
    object : MouseAdapter() {
      override fun mouseClicked(event: MouseEvent) {
        if (event.clickCount != 2 || event.isPopupTrigger) {
          return
        }
        var row = table.rowAtPoint(event.point)
        if (row < 0) {
          return
        }
        var column = table.columnAtPoint(event.point)
        if (column >= 0 && table.getValueAt(row, column) is Boolean) {
          return
        }
        table.setRowSelectionInterval(row, row)
        editAction.actionPerformed(
          ActionEvent(table, ActionEvent.ACTION_PERFORMED, EDIT_ACTION_COMMAND)
        )
      }
    }

  companion object {
    private const val TABLE_MINIMUM_WIDTH = 200
    private const val TABLE_MINIMUM_HEIGHT = 60
    private const val TABLE_PREFERRED_WIDTH = 800
    private const val TABLE_PREFERRED_HEIGHT = 150
    private const val FILTER_HEIGHT = 30
    private const val EDIT_ACTION_COMMAND = "edit"
  }
}
