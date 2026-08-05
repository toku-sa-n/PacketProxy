/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.gui

import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.event.ActionListener
import java.awt.event.MouseAdapter
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JTable
import javax.swing.RowFilter
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.TableRowSorter
import packetproxy.common.*
import packetproxy.model.OptionTableModel

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
    table.rowHeight = owner.modelServices.fontManager.getUIFontHeight(table)

    val scrollPane = CustomScrollPane()
    scrollPane.setViewportView(table)
    scrollPane.background = Color.WHITE
    scrollPane.minimumSize = Dimension(800, 150)
    scrollPane.preferredSize = Dimension(800, 150)
    scrollPane.maximumSize = Dimension(800, 150)
    scrollPane.alignmentY = Component.TOP_ALIGNMENT

    panel.add(createTableButton(addAction, editAction, removeAction))
    if (searchable) {
      val filterText = HintTextField(i18nString("Incremental Search for Host"))
      filterText.minimumSize = Dimension(800, 30)
      filterText.preferredSize = Dimension(800, 30)
      filterText.maximumSize = Dimension(800, 30)
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
      subPanel.background = Color.WHITE
      panel.add(subPanel)
    } else {
      panel.add(scrollPane)
    }
    panel.background = Color.WHITE
    panel.maximumSize = Dimension(Short.MAX_VALUE.toInt(), panel.minimumSize.height)
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
      edit.addActionListener(editAction)
    }
    if (removeAction != null) {
      panel.add(remove)
      remove.addActionListener(removeAction)
    }
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.background = Color.WHITE
    panel.maximumSize = Dimension(100, panel.minimumSize.height)
    panel.alignmentY = Component.TOP_ALIGNMENT
    return panel
  }

  override fun propertyChange(evt: PropertyChangeEvent) = updateImpl()

  protected abstract fun clearTableContents()

  protected abstract fun getTableContent(rowIndex: Int): T

  protected abstract fun getSelectedTableContent(): T?

  protected abstract fun addTableContent(value: T)

  protected abstract fun updateTable(values: List<T>)

  protected abstract fun updateImpl()
}
