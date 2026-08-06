package packetproxy.gui

import java.awt.BorderLayout
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import javax.swing.JButton
import javax.swing.JPanel
import javax.swing.JTabbedPane
import packetproxy.common.Range
import packetproxy.common.i18nString
import packetproxy.model.PropertyChangeEventType.SELECTED_INDEX
import packetproxy.util.SearchBox
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class TabSet(private val owner: GUIMain, search: Boolean, copy: Boolean) {
  private companion object {
    private const val RAW_TAB_INDEX = 0
    private const val BINARY_TAB_INDEX = 1
    private const val JSON_TAB_INDEX = 2
    private const val IMAGE_TAB_INDEX = 3

    /** Raw/Binary/Json/Imageの4つ。この後ろにHTTP構造化タブが並ぶので既存のタブ番号は変わらない。 */
    private const val FIXED_TAB_COUNT = 4
  }

  private val changes = PropertyChangeSupport(this)
  private val rawPanel = GUIHistoryRaw(owner)
  private val binaryPanel = GUIHistoryBinary(owner)
  private val jsonPanel = GUIJson(owner)
  private val imagePanel = GUIImagePanel()
  private val structuredTabs = HttpStructuredTabs(owner)
  private val dataPane = JTabbedPane()
  private val basePanel = JPanel(BorderLayout())
  private var copyButton: JButton? = null
  private var parentSendButton: JButton? = null
  private var data: ByteArray? = null
  private var emphasis: Range? = null
  private var searchBox: SearchBox? = null
  private var structuredKinds: List<HttpStructuredTabKind> = emptyList()
  private var syncingStructuredTabs = false

  init {
    rawPanel.setParentTabs(this)
    binaryPanel.setParentTabs(this)
    dataPane.addTab(i18nString("Raw"), rawPanel.createPanel())
    dataPane.addTab(i18nString("Binary"), binaryPanel.createPanel())
    dataPane.addTab(i18nString("Json"), jsonPanel.createPanel())
    dataPane.addTab(i18nString("Image"), imagePanel.createPanel())
    dataPane.setEnabledAt(IMAGE_TAB_INDEX, false)
    dataPane.addChangeListener {
      if (syncingStructuredTabs) {
        return@addChangeListener
      }
      try {
        update()
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }
    basePanel.add(dataPane)
    if (search) {
      searchBox = SearchBox(owner.modelServices.fontManager)
      basePanel.add(searchBox, BorderLayout.SOUTH)
    }
    if (copy) {
      copyButton = JButton(i18nString("copy to clipboard"))
      basePanel.add(copyButton)
    }
  }

  val tabPanel: JPanel
    get() = basePanel

  val raw: GUIHistoryRaw
    get() = rawPanel

  val binary: GUIHistoryBinary
    get() = binaryPanel

  val json: GUIJson
    get() = jsonPanel

  val selectedIndex: Int
    get() = dataPane.selectedIndex

  fun getData(): ByteArray {
    if (data == null) {
      return ByteArray(0)
    }
    return when (selectedIndex) {
      RAW_TAB_INDEX -> rawPanel.getData()
      BINARY_TAB_INDEX -> binaryPanel.getData()
      JSON_TAB_INDEX -> jsonPanel.getData()
      /* 画像タブは編集できないので、渡された内容をそのまま返す */
      IMAGE_TAB_INDEX -> data ?: ByteArray(0)
      /* HTTP構造化タブは読み取り専用なので、Rawタブが持っている内容をそのまま返す */
      else -> rawPanel.getData()
    }
  }

  fun setData(data: ByteArray, emphasis: Range?) {
    this.data = data
    this.emphasis = emphasis
    syncStructuredTabs(data)
    syncImageTab(data)
    update()
  }

  fun setData(data: ByteArray) {
    this.data = data
    emphasis = null
    syncStructuredTabs(data)
    syncImageTab(data)
    update()
  }

  val parentSend: JButton?
    get() = parentSendButton

  fun setParentSend(parentSend: JButton?) {
    parentSendButton = parentSend
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  fun firePropertyChange(newValue: Any?) {
    changes.firePropertyChange(SELECTED_INDEX.toString(), null, newValue)
  }

  /** HTTPに見えるデータのときだけ、固定タブの後ろに構造化タブを並べ替える。 */
  private fun syncStructuredTabs(data: ByteArray) {
    var kinds = structuredTabs.setData(data)
    if (kinds == structuredKinds) {
      return
    }
    var selectedKind = structuredKindAt(selectedIndex)
    syncingStructuredTabs = true
    try {
      while (dataPane.tabCount > FIXED_TAB_COUNT) {
        dataPane.removeTabAt(dataPane.tabCount - 1)
      }
      kinds.forEach { dataPane.addTab(i18nString(it.title), structuredTabs.panelOf(it)) }
      structuredKinds = kinds
      /* 選択中だったタブが残っているなら選び直して、履歴を辿るたびにRawへ戻らないようにする */
      var restored = kinds.indexOf(selectedKind)
      if (restored >= 0) {
        dataPane.selectedIndex = FIXED_TAB_COUNT + restored
      }
    } finally {
      syncingStructuredTabs = false
    }
  }

  /** 画像として表示できるデータのときだけImageタブを選択できるようにする。 */
  private fun syncImageTab(data: ByteArray) {
    val isImage = GUIImagePanel.extractImageBytes(data) != null
    dataPane.setEnabledAt(IMAGE_TAB_INDEX, isImage)
    if (isImage || selectedIndex != IMAGE_TAB_INDEX) {
      return
    }
    dataPane.selectedIndex = RAW_TAB_INDEX
  }

  private fun structuredKindAt(index: Int): HttpStructuredTabKind? {
    if (index < FIXED_TAB_COUNT) {
      return null
    }
    return structuredKinds.getOrNull(index - FIXED_TAB_COUNT)
  }

  private fun update() {
    val currentData = data ?: return
    try {
      updateSelectedPanel(currentData)
      updateSearchBox()
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
    firePropertyChange(selectedIndex)
  }

  private fun updateSelectedPanel(currentData: ByteArray) {
    if (structuredKindAt(selectedIndex) != null) {
      /* 構造化タブ自体はsyncStructuredTabsで更新済み。getData()が最新を返すようRawにも流し込む */
      rawPanel.setData(currentData)
      return
    }
    when (selectedIndex) {
      RAW_TAB_INDEX -> rawPanel.setData(currentData)
      BINARY_TAB_INDEX -> binaryPanel.setData(currentData)
      JSON_TAB_INDEX ->
        jsonPanel.setData(
          owner.coreServices.packetProxyUtility.prettyFormatJSONInRawData(currentData)
        )
      IMAGE_TAB_INDEX -> imagePanel.setData(currentData)
      else -> log("Not effective index, though this returns raw_panel data in such case.")
    }
  }

  private fun updateSearchBox() {
    val currentSearchBox = searchBox ?: return
    when {
      /* テーブル表示なのでテキスト検索の対象にできない */
      structuredKindAt(selectedIndex) != null -> currentSearchBox.isVisible = false
      selectedIndex == RAW_TAB_INDEX -> {
        currentSearchBox.isVisible = true
        currentSearchBox.setBaseText(rawPanel.getTextPane(), emphasis ?: Range.of(0, 0))
      }
      selectedIndex == BINARY_TAB_INDEX -> currentSearchBox.isVisible = false
      /* 画像表示なのでテキスト検索の対象にできない */
      selectedIndex == IMAGE_TAB_INDEX -> currentSearchBox.isVisible = false
      selectedIndex == JSON_TAB_INDEX -> {
        currentSearchBox.isVisible = true
        currentSearchBox.setBaseText(jsonPanel.getTextPane(), emphasis ?: Range.of(0, 0))
      }
      else -> log("Not effective index, though this returns raw_panel data in such case.")
    }
    currentSearchBox.textChanged()
  }
}
