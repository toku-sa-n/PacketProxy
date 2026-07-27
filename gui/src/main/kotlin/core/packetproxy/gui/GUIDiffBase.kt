package packetproxy.gui

import java.awt.Color
import java.awt.GridLayout
import java.awt.event.ActionListener
import javax.swing.*
import javax.swing.text.MutableAttributeSet
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import javax.swing.text.StyledDocument
import packetproxy.model.DiffSet
import packetproxy.util.Logging.errWithStackTrace

abstract class GUIDiffBase {
  protected var width = 0
  protected var height = 0
  protected var panel: JComponent
  protected var mainPanel: JPanel
  protected var textOrig: RawTextPane
  protected var textTarg: RawTextPane
  protected lateinit var docOrig: StyledDocument
  protected lateinit var docTarg: StyledDocument
  protected var scrollOrig: JScrollPane
  protected var scrollTarg: JScrollPane
  protected var delAttr: MutableAttributeSet
  protected var insAttr: MutableAttributeSet
  protected var chgAttr: MutableAttributeSet
  protected var defaultAttr: MutableAttributeSet
  protected var jc: JCheckBox
  protected var jcPanel: JPanel

  init {
    var panelOrig = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
    textOrig = RawTextPane().apply { isEditable = true }
    panelOrig.add(JLabel("Original").apply { alignmentX = 0.5f })
    scrollOrig =
      JScrollPane(textOrig).apply {
        verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
      }
    panelOrig.add(scrollOrig)
    var panelTarg = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
    textTarg = RawTextPane().apply { isEditable = true }
    panelTarg.add(JLabel("Target").apply { alignmentX = 0.5f })
    scrollTarg =
      JScrollPane(textTarg).apply {
        verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
      }
    panelTarg.add(scrollTarg)
    mainPanel =
      JPanel(GridLayout(1, 2)).apply {
        add(panelOrig)
        add(panelTarg)
      }
    jc =
      JCheckBox("Sort & Uniq").apply {
        addActionListener(
          ActionListener {
            try {
              update()
            } catch (e: Exception) {
              errWithStackTrace(e)
            }
          }
        )
      }
    jcPanel =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.LINE_AXIS)
        add(jc)
      }
    panel =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(mainPanel)
        add(jcPanel)
      }
    delAttr = SimpleAttributeSet().also { StyleConstants.setBackground(it, Color.RED) }
    chgAttr = SimpleAttributeSet().also { StyleConstants.setBackground(it, Color.YELLOW) }
    insAttr = SimpleAttributeSet().also { StyleConstants.setBackground(it, Color.GREEN) }
    defaultAttr = SimpleAttributeSet().also { StyleConstants.setBackground(it, Color.WHITE) }
  }

  fun createPanel(): JComponent = panel

  protected fun sortUniq(str: String): String =
    str.split("\n").filter { it.isNotEmpty() }.toSortedSet().joinToString("\n")

  protected abstract fun sortUniq(ds: DiffSet): DiffSet

  abstract fun update()
}
