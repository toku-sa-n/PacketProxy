package packetproxy.gui

import java.awt.GridLayout
import java.awt.event.ActionListener
import javax.swing.*
import javax.swing.text.MutableAttributeSet
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import javax.swing.text.StyledDocument
import packetproxy.common.i18nString
import packetproxy.model.DiffSet
import packetproxy.util.errWithStackTrace

abstract class GUIDiffBase(protected val owner: GUIMain) {
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
  protected var jcSyncScroll: JCheckBox
  protected var jcPanel: JPanel
  // 同期スクロールで相手側を動かしたことによる再帰的な通知を無視するためのフラグ
  private var syncingScroll = false

  init {
    var panelOrig = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
    textOrig =
      RawTextPane(
          owner,
          owner.modelServices.fontManager,
          owner.modelServices.charSetUtility,
          owner.coreServices.packetProxyUtility,
        )
        .apply { isEditable = true }
    panelOrig.add(JLabel(i18nString("Original")).apply { alignmentX = 0.5f })
    scrollOrig =
      JScrollPane(textOrig).apply {
        verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
      }
    panelOrig.add(scrollOrig)
    var panelTarg = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
    textTarg =
      RawTextPane(
          owner,
          owner.modelServices.fontManager,
          owner.modelServices.charSetUtility,
          owner.coreServices.packetProxyUtility,
        )
        .apply { isEditable = true }
    panelTarg.add(JLabel(i18nString("Target")).apply { alignmentX = 0.5f })
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
      JCheckBox(i18nString("Sort & Uniq")).apply {
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
    jcSyncScroll = JCheckBox(i18nString("Sync scroll"), true)
    jcPanel =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.LINE_AXIS)
        add(jc)
        add(JLabel("    "))
        add(jcSyncScroll)
      }
    syncScrollBars(scrollOrig, scrollTarg)
    syncScrollBars(scrollTarg, scrollOrig)
    panel =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(mainPanel)
        add(jcPanel)
      }
    delAttr =
      SimpleAttributeSet().also {
        StyleConstants.setBackground(it, ThemeColors.diffRemoveBackground())
      }
    chgAttr =
      SimpleAttributeSet().also {
        StyleConstants.setBackground(it, ThemeColors.diffChangeBackground())
      }
    insAttr =
      SimpleAttributeSet().also {
        StyleConstants.setBackground(it, ThemeColors.diffAddBackground())
      }
    defaultAttr =
      SimpleAttributeSet().also {
        StyleConstants.setBackground(it, ThemeColors.diffDefaultBackground())
      }
  }

  fun createPanel(): JComponent = panel

  /** source側のスクロール位置をtarget側へ伝搬させる。行数が違っても比率で合わせる */
  private fun syncScrollBars(source: JScrollPane, target: JScrollPane) {
    source.verticalScrollBar.addAdjustmentListener { event ->
      if (!jcSyncScroll.isSelected || syncingScroll) {
        return@addAdjustmentListener
      }
      var sourceBar = source.verticalScrollBar
      var targetBar = target.verticalScrollBar
      var sourceRange = sourceBar.maximum - sourceBar.visibleAmount
      var targetRange = targetBar.maximum - targetBar.visibleAmount
      if (sourceRange <= 0 || targetRange <= 0) {
        return@addAdjustmentListener
      }
      syncingScroll = true
      try {
        targetBar.value = (event.value.toLong() * targetRange / sourceRange).toInt()
      } finally {
        syncingScroll = false
      }
    }
  }

  protected fun sortUniq(str: String): String =
    str.split("\n").filter { it.isNotEmpty() }.toSortedSet().joinToString("\n")

  protected abstract fun sortUniq(ds: DiffSet): DiffSet

  abstract fun update()
}
