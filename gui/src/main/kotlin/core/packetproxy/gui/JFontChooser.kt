/*
 * Copyright 2004-2005,2007-2008 Masahiko SAWAI All Rights Reserved.
 */
package packetproxy.gui

import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import java.awt.Frame
import java.awt.GraphicsEnvironment
import java.awt.GridLayout
import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import javax.swing.AbstractAction
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.KeyStroke
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.text.BadLocationException
import javax.swing.text.Position
import packetproxy.common.*
import packetproxy.util.errWithStackTrace

class JFontChooser(preset: Font = DEFAULT_SELECTED_FONT) : JComponent() {
  private val fontFamilies =
    GraphicsEnvironment.getLocalGraphicsEnvironment().availableFontFamilyNames
  private val fontSizes = DEFAULT_FONT_SIZE_STRINGS
  private val fontFamilyTextField = JTextField().apply { font = DEFAULT_FONT }
  private val fontSizeTextField = JTextField().apply { font = DEFAULT_FONT }
  private val fontFamilyList =
    JList(fontFamilies).apply { selectionMode = ListSelectionModel.SINGLE_SELECTION }
  private val fontSizeList =
    JList(fontSizes).apply { selectionMode = ListSelectionModel.SINGLE_SELECTION }
  private val sampleText = JTextField("AaBbYyZz")
  private var dialogResultValue = ERROR_OPTION

  init {
    fontFamilyTextField.addFocusListener(SelectAllFocusListener(fontFamilyTextField))
    fontSizeTextField.addFocusListener(SelectAllFocusListener(fontSizeTextField))
    fontFamilyTextField.addKeyListener(ListNavigationKeyListener(fontFamilyList))
    fontSizeTextField.addKeyListener(ListNavigationKeyListener(fontSizeList))
    fontFamilyTextField.document.addDocumentListener(ListSearchListener(fontFamilyList))
    fontSizeTextField.document.addDocumentListener(ListSearchListener(fontSizeList))
    fontFamilyList.addListSelectionListener { event ->
      if (!event.valueIsAdjusting) {
        fontFamilyTextField.text = fontFamilyList.selectedValue
        updateSampleFont()
      }
    }
    fontSizeList.addListSelectionListener { event ->
      if (!event.valueIsAdjusting) {
        fontSizeTextField.text = fontSizeList.selectedValue
        updateSampleFont()
      }
    }
    fontFamilyList.selectedIndex = 0
    fontSizeList.selectedIndex = 0
    layout = BoxLayout(this, BoxLayout.X_AXIS)
    border = BorderFactory.createEmptyBorder(5, 5, 5, 5)
    add(
      JPanel(GridLayout(2, 1)).apply {
        add(
          JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            add(
              createPanel(
                i18nString("Font Name"),
                fontFamilyTextField,
                fontFamilyList,
                Dimension(200, 200),
              )
            )
            add(
              createPanel(
                i18nString("Font Size"),
                fontSizeTextField,
                fontSizeList,
                Dimension(100, 200),
              )
            )
          }
        )
        add(
          JPanel(BorderLayout()).apply {
            preferredSize = Dimension(200, 50)
            border = BorderFactory.createEmptyBorder(5, 5, 5, 5)
            add(JLabel(i18nString("Sample")), BorderLayout.NORTH)
            add(sampleText, BorderLayout.CENTER)
          }
        )
      }
    )
    setSelectedFont(preset)
  }

  fun getFontFamilyTextField(): JTextField = fontFamilyTextField

  fun getFontSizeTextField(): JTextField = fontSizeTextField

  fun getFontFamilyList(): JList<String> = fontFamilyList

  fun getFontSizeList(): JList<String> = fontSizeList

  fun getSelectedFontFamily(): String = fontFamilyList.selectedValue

  fun getSelectedFontSize(): Int =
    fontSizeTextField.text.toIntOrNull() ?: fontSizeList.selectedValue.toInt()

  fun getSelectedFont(): Font = Font(getSelectedFontFamily(), Font.PLAIN, getSelectedFontSize())

  fun setSelectedFontFamily(name: String) {
    fontFamilies
      .indexOfFirst { it.equals(name, ignoreCase = true) }
      .takeIf { it >= 0 }
      ?.let { fontFamilyList.selectedIndex = it }
    updateSampleFont()
  }

  fun setSelectedFontSize(size: Int) {
    fontSizes.indexOf(size.toString()).takeIf { it >= 0 }?.let { fontSizeList.selectedIndex = it }
    fontSizeTextField.text = size.toString()
    updateSampleFont()
  }

  fun setSelectedFont(font: Font) {
    setSelectedFontFamily(font.family)
    setSelectedFontSize(font.size)
  }

  fun showDialog(parent: Component): Int {
    dialogResultValue = ERROR_OPTION
    val dialog = createDialog(parent)
    dialog.addWindowListener(
      object : WindowAdapter() {
        override fun windowClosing(event: WindowEvent) {
          dialogResultValue = CANCEL_OPTION
        }
      }
    )
    dialog.isVisible = true
    dialog.dispose()
    return dialogResultValue
  }

  internal fun createDialog(parent: Component): JDialog {
    val frame =
      if (parent is Frame) parent
      else SwingUtilities.getAncestorOfClass(Frame::class.java, parent) as? Frame
    val dialog = JDialog(frame, i18nString("Font Setting"), true)
    val okAction = DialogAction(dialog, OK_OPTION, "OK")
    val cancelAction = DialogAction(dialog, CANCEL_OPTION, "Cancel")
    val buttons =
      JPanel(GridLayout(2, 1)).apply {
        add(JButton(okAction).apply { font = DEFAULT_FONT })
        add(JButton(cancelAction).apply { font = DEFAULT_FONT })
        border = BorderFactory.createEmptyBorder(25, 0, 10, 10)
        actionMap.put("OK", okAction)
        actionMap.put("Cancel", cancelAction)
        getInputMap(WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("ESCAPE"), "Cancel")
        getInputMap(WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("ENTER"), "OK")
      }
    dialog.contentPane.add(this, BorderLayout.CENTER)
    dialog.contentPane.add(
      JPanel(BorderLayout()).apply { add(buttons, BorderLayout.NORTH) },
      BorderLayout.EAST,
    )
    dialog.pack()
    dialog.setLocationRelativeTo(frame)
    return dialog
  }

  internal fun updateSampleFont() {
    sampleText.font = getSelectedFont()
  }

  private fun createPanel(title: String, field: JTextField, list: JList<String>, size: Dimension) =
    JPanel(BorderLayout()).apply {
      preferredSize = size
      border = BorderFactory.createEmptyBorder(5, 5, 5, 5)
      add(JLabel(title), BorderLayout.NORTH)
      add(
        JPanel(BorderLayout()).apply {
          add(field, BorderLayout.NORTH)
          add(
            JScrollPane(list).apply {
              verticalScrollBar.isFocusable = false
              verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_ALWAYS
            },
            BorderLayout.CENTER,
          )
        },
        BorderLayout.CENTER,
      )
    }

  private inner class DialogAction(
    private val dialog: JDialog,
    private val result: Int,
    name: String,
  ) : AbstractAction(name) {
    override fun actionPerformed(event: java.awt.event.ActionEvent) {
      dialogResultValue = result
      dialog.isVisible = false
    }
  }

  private inner class SelectAllFocusListener(private val field: JTextField) : FocusAdapter() {
    override fun focusGained(event: FocusEvent) = field.selectAll()

    override fun focusLost(event: FocusEvent) {
      field.select(0, 0)
      updateSampleFont()
    }
  }

  private class ListNavigationKeyListener(private val list: JList<String>) : KeyAdapter() {
    override fun keyPressed(event: KeyEvent) {
      val index =
        when (event.keyCode) {
          KeyEvent.VK_UP -> (list.selectedIndex - 1).coerceAtLeast(0)
          KeyEvent.VK_DOWN -> (list.selectedIndex + 1).coerceAtMost(list.model.size - 1)
          else -> return
        }
      list.selectedIndex = index
    }
  }

  private class ListSearchListener(private val list: JList<String>) : DocumentListener {
    override fun insertUpdate(event: DocumentEvent) = update(event)

    override fun removeUpdate(event: DocumentEvent) = update(event)

    override fun changedUpdate(event: DocumentEvent) = update(event)

    private fun update(event: DocumentEvent) {
      try {
        val value = event.document.getText(0, event.document.length)
        if (value.isEmpty()) return
        val index = list.getNextMatch(value, 0, Position.Bias.Forward).coerceAtLeast(0)
        list.ensureIndexIsVisible(index)
        if (
          value.equals(list.model.getElementAt(index), ignoreCase = true) &&
            index != list.selectedIndex
        ) {
          SwingUtilities.invokeLater { list.selectedIndex = index }
        }
      } catch (exception: BadLocationException) {
        errWithStackTrace(exception)
      }
    }
  }

  companion object {
    const val OK_OPTION = 0
    const val CANCEL_OPTION = 1
    const val ERROR_OPTION = -1
    private val DEFAULT_SELECTED_FONT = Font("Serif", Font.PLAIN, 12)
    private val DEFAULT_FONT = Font("Dialog", Font.PLAIN, 10)
    private val DEFAULT_FONT_SIZE_STRINGS =
      arrayOf(
        "8",
        "9",
        "10",
        "11",
        "12",
        "13",
        "14",
        "16",
        "18",
        "20",
        "22",
        "24",
        "26",
        "28",
        "36",
      )
  }
}
