/*
 * Copyright 2025 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.gui

import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.event.MouseMotionAdapter
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.util.Objects
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.UIManager
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import packetproxy.common.I18nString
import packetproxy.util.Logging.errWithStackTrace

class GUIProjectChooserDialog(private val owner: JFrame) {
  private val projects = Projects()

  @Throws(Exception::class)
  fun chooseAndSetup(): Boolean {
    while (true) {
      val result = booleanArrayOf(false)
      val decided = booleanArrayOf(false)
      val shouldExit = booleanArrayOf(false)
      val dialog =
        JDialog(owner, I18nString.get("Welcome"), true).apply {
          defaultCloseOperation = JDialog.DO_NOTHING_ON_CLOSE
          addWindowListener(
            object : WindowAdapter() {
              override fun windowClosing(event: WindowEvent) {
                shouldExit[0] = true
                dispose()
              }
            }
          )
        }
      val content = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
      content.add(
        button(I18nString.get("Temporary project")) {
          try {
            projects.createTemporaryProject()
            result[0] = false
            decided[0] = true
            dialog.dispose()
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      )
      content.add(
        button(I18nString.get("Create new project")) {
          try {
            if (!setupNewProject(dialog)) return@button
            result[0] = false
            decided[0] = true
            dialog.dispose()
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      )
      content.add(
        button(I18nString.get("Open previous project")) {
          try {
            if (!openByFileChooser(dialog)) return@button
            result[0] = true
            decided[0] = true
            dialog.dispose()
          } catch (exception: Exception) {
            showOpenError(dialog, exception)
          }
        }
      )
      addRecentProjects(content, dialog, result, decided)
      dialog.contentPane = JScrollPane(content)
      dialog.pack()
      dialog.setLocationRelativeTo(owner)
      dialog.isVisible = true
      if (decided[0]) return result[0]
      if (shouldExit[0]) System.exit(0)
    }
  }

  private fun addRecentProjects(
    content: JPanel,
    dialog: JDialog,
    result: BooleanArray,
    decided: BooleanArray,
  ) {
    val recentProjects = projects.getValidRecentProjects()
    if (recentProjects.isEmpty()) return
    content.add(
      wrap(
        JLabel(I18nString.get("Recent Projects")).apply {
          font = font.deriveFont(Font.BOLD, 13f)
          border = BorderFactory.createEmptyBorder(10, 5, 5, 5)
        }
      )
    )
    val model = DefaultListModel<Projects.ProjectInfo>()
    recentProjects.forEach { model.addElement(it) }
    val projectList = JList(model)
    val renderer = RecentProjectCellRenderer()
    projectList.cellRenderer = renderer
    projectList.isFocusable = false
    projectList.addMouseListener(
      object : MouseAdapter() {
        override fun mousePressed(event: MouseEvent) {
          val index = validIndex(projectList, event) ?: return
          try {
            projects.openProject(model.getElementAt(index).getPath())
            result[0] = true
            decided[0] = true
            dialog.dispose()
          } catch (exception: Exception) {
            showOpenError(dialog, exception)
          }
        }

        override fun mouseExited(event: MouseEvent) {
          renderer.hoveredIndex = -1
          projectList.cursor = java.awt.Cursor.getDefaultCursor()
          projectList.repaint()
        }
      }
    )
    projectList.addMouseMotionListener(
      object : MouseMotionAdapter() {
        override fun mouseMoved(event: MouseEvent) {
          val index = validIndex(projectList, event) ?: -1
          renderer.hoveredIndex = index
          projectList.cursor =
            if (index < 0) java.awt.Cursor.getDefaultCursor()
            else java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR)
          projectList.repaint()
        }
      }
    )
    content.add(
      wrap(
        JScrollPane(projectList).apply {
          preferredSize = Dimension(700, 280)
          border = BorderFactory.createLineBorder(Color.LIGHT_GRAY)
          viewport.isOpaque = true
          projectList.isOpaque = true
        }
      )
    )
  }

  private fun validIndex(list: JList<*>, event: MouseEvent): Int? {
    val index = list.locationToIndex(event.point)
    if (index < 0) return null
    return index.takeIf { list.getCellBounds(it, it)?.contains(event.point) == true }
  }

  private fun button(text: String, action: () -> Unit) =
    wrap(
      JButton(text).apply {
        alignmentX = Component.CENTER_ALIGNMENT
        addActionListener { action() }
      }
    )

  private fun wrap(component: Component) =
    JPanel().apply {
      layout = BoxLayout(this, BoxLayout.X_AXIS)
      add(component)
      component.maximumSize = Dimension(Int.MAX_VALUE, component.preferredSize.height)
    }

  @Throws(Exception::class)
  private fun setupNewProject(parent: Component): Boolean {
    val panel = JPanel(GridBagLayout())
    val constraints =
      GridBagConstraints().apply {
        anchor = GridBagConstraints.WEST
        insets = Insets(5, 5, 5, 5)
      }
    panel.add(JLabel("${I18nString.get("Enter project name")}:"), constraints)
    val textField = JTextField(20)
    constraints.apply {
      gridy = 1
      fill = GridBagConstraints.HORIZONTAL
      weightx = 1.0
    }
    panel.add(textField, constraints)
    val optionPane = JOptionPane(panel, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION)
    val dialog = optionPane.createDialog(parent, I18nString.get("Create Project"))
    findOkButton(optionPane)?.let { okButton ->
      okButton.isEnabled = false
      textField.document.addDocumentListener(
        object : DocumentListener {
          override fun insertUpdate(event: DocumentEvent) = update()

          override fun removeUpdate(event: DocumentEvent) = update()

          override fun changedUpdate(event: DocumentEvent) = update()

          private fun update() {
            okButton.isEnabled = textField.text.trim().isNotEmpty()
          }
        }
      )
    }
    dialog.isVisible = true
    if (!Objects.equals(optionPane.value, JOptionPane.OK_OPTION)) return false
    val name = textField.text.trim()
    if (name.isEmpty()) return false
    projects.createNewProject(name)
    return true
  }

  private fun findOkButton(optionPane: JOptionPane): JButton? =
    optionPane.components
      .filterIsInstance<JPanel>()
      .flatMap { it.components.asIterable() }
      .filterIsInstance<JButton>()
      .firstOrNull { it.text == "OK" || it.text == UIManager.getString("OptionPane.okButtonText") }

  @Throws(Exception::class)
  private fun openByFileChooser(parent: Component): Boolean {
    val chooser = NativeFileChooser()
    chooser.addChoosableFileFilter("*.sqlite3", "sqlite3")
    chooser.setAcceptAllFileFilterUsed(false)
    if (chooser.showOpenDialog(parent) != NativeFileChooser.APPROVE_OPTION) return false
    return try {
      projects.openProject(requireNotNull(chooser.getSelectedFile()).absolutePath)
      true
    } catch (exception: Exception) {
      showOpenError(parent, exception)
      false
    }
  }

  private fun showOpenError(parent: Component, exception: Exception) {
    errWithStackTrace(exception)
    JOptionPane.showMessageDialog(
      parent,
      "${I18nString.get("Failed to open project")}\n${exception.message}",
      I18nString.get("Error"),
      JOptionPane.ERROR_MESSAGE,
    )
  }

  private class RecentProjectCellRenderer : DefaultListCellRenderer() {
    var hoveredIndex = -1

    override fun getListCellRendererComponent(
      list: JList<*>,
      value: Any?,
      index: Int,
      isSelected: Boolean,
      cellHasFocus: Boolean,
    ): Component {
      val info =
        value as? Projects.ProjectInfo
          ?: return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
      return JPanel(GridBagLayout()).apply {
        border = BorderFactory.createEmptyBorder(8, 10, 8, 10)
        val constraints =
          GridBagConstraints().apply {
            fill = GridBagConstraints.HORIZONTAL
            anchor = GridBagConstraints.WEST
            gridwidth = 2
            weightx = 1.0
          }
        add(JLabel(info.getName()).apply { font = font.deriveFont(Font.BOLD, 14f) }, constraints)
        constraints.apply {
          gridy = 1
          gridwidth = 1
          weightx = 0.0
        }
        add(JLabel("${I18nString.get("Path")}: ").apply { foreground = Color.GRAY }, constraints)
        constraints.apply {
          gridx = 1
          weightx = 1.0
        }
        add(JLabel(info.getPath()).apply { foreground = Color.GRAY }, constraints)
        constraints.apply {
          gridx = 0
          gridy = 2
          weightx = 0.0
        }
        add(
          JLabel("${I18nString.get("Last modified")}: ").apply { foreground = Color.GRAY },
          constraints,
        )
        constraints.apply {
          gridx = 1
          weightx = 1.0
        }
        add(JLabel(info.getLastModified()).apply { foreground = Color.GRAY }, constraints)
        isOpaque = index == hoveredIndex
        if (isOpaque) background = Color(230, 240, 255)
      }
    }
  }
}
