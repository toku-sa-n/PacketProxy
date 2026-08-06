/*
 * Copyright 2019 DeNA Co., Ltd.
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
package packetproxy.util

import java.awt.Dimension
import java.awt.Toolkit
import java.awt.event.ActionEvent
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import javax.swing.AbstractAction
import javax.swing.ActionMap
import javax.swing.BoxLayout
import javax.swing.InputMap
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.JTextPane
import javax.swing.KeyStroke
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import packetproxy.common.FontManager
import packetproxy.common.Range
import packetproxy.common.i18nString
import packetproxy.gui.ThemeColors

/**
 * 本文の下に置く検索ボックス。
 *
 * 画面に追加された時点で、検索ボックスを載せた親コンテナに Ctrl/Cmd+F（検索欄へフォーカス）、F3（次の一致）、 Shift+F3（前の一致）を登録する。
 * WHEN_ANCESTOR_OF_FOCUSED_COMPONENT で登録するため、呼び出し側は 検索対象の本文と同じコンテナに add
 * するだけでよく、同一ウィンドウ内の他の検索ボックスとも干渉しない。
 */
class SearchBox(private val fontManager: FontManager) : JPanel() {
  private var baseText: JTextPane? = null
  private var emphasisArea: Range? = null
  private val searchText = JTextField()
  private val searchCount = JLabel(i18nString("Not found"))
  private var previousWord: String? = null
  private var currentPosition = -1

  init {
    searchText.font = fontManager.getFont()
    searchText.addKeyListener(
      object : KeyAdapter() {
        override fun keyReleased(event: KeyEvent) {
          try {
            searchText.font = fontManager.getFont()
            updateSearchText()
            if (event.keyCode != KeyEvent.VK_ENTER) return
            if (event.isShiftDown) findPrevious() else findNext()
          } catch (e: Exception) {
            Logging.errWithStackTrace(e)
          }
        }
      }
    )
    searchCount.isOpaque = true
    searchCount.font = fontManager.getUIFont()
    searchCount.horizontalAlignment = JLabel.CENTER
    applyCountLabelSize()

    layout = BoxLayout(this, BoxLayout.X_AXIS)
    add(searchText)
    add(searchCount)
  }

  override fun addNotify() {
    super.addNotify()
    registerShortcuts(parent as? JComponent)
  }

  fun setBaseText(textPane: JTextPane) {
    baseText = textPane
    emphasisArea = null
  }

  fun setBaseText(textPane: JTextPane, emphasisArea: Range) {
    baseText = textPane
    this.emphasisArea = emphasisArea
  }

  fun setText(text: String) {
    searchText.text = text
  }

  fun getText(): String = searchText.text

  fun focusSearchText() {
    searchText.requestFocusInWindow()
    searchText.selectAll()
  }

  /** 次の一致へ移動する。末尾に達したら先頭に戻る。 */
  fun findNext() {
    moveToMatch(true)
  }

  /** 前の一致へ移動する。先頭に達したら末尾に戻る。 */
  fun findPrevious() {
    moveToMatch(false)
  }

  fun coloringSearchText(): Int {
    val textPane = baseText ?: return 0
    val document = textPane.styledDocument
    val text = textPane.text
    val searchString = searchText.text
    if (text.length > MAX_TEXT_LENGTH_FOR_HIGHLIGHTING) return -1
    if (text.isEmpty() || searchString.isEmpty()) return 0

    val attributes = SimpleAttributeSet()
    var count = 0
    var start = 0
    while (true) {
      start = text.indexOf(searchString, start)
      if (start < 0) break

      count++
      StyleConstants.setBackground(attributes, ThemeColors.searchHighlight())
      document.setCharacterAttributes(start, searchString.length, attributes, false)
      start += searchString.length
    }
    return count
  }

  fun coloringEmphasis() {
    val area = emphasisArea ?: return
    val document = baseText!!.styledDocument
    val attributes = SimpleAttributeSet()
    StyleConstants.setForeground(attributes, ThemeColors.emphasisForeground())
    StyleConstants.setBold(attributes, true)
    val start = area.getPositionStart()
    val end = area.getPositionEnd()
    document.setCharacterAttributes(start, end - start, attributes, false)
  }

  fun coloringClear() {
    val document = baseText!!.styledDocument
    val text = baseText!!.text
    val attributes = SimpleAttributeSet()
    StyleConstants.setForeground(attributes, ThemeColors.textForeground())
    StyleConstants.setBackground(attributes, ThemeColors.textBackground())
    StyleConstants.setBold(attributes, false)
    document.setCharacterAttributes(0, text.length, attributes, false)
  }

  fun coloringBackgroundClear() {
    val document = baseText!!.styledDocument
    val text = baseText!!.text
    val attributes = SimpleAttributeSet()
    StyleConstants.setBackground(attributes, ThemeColors.textBackground())
    document.setCharacterAttributes(0, text.length, attributes, false)
  }

  /** HTTP structure-aware exclusion of non-parameter regions is unsupported. */
  fun coloringHTTPText() {
    val document = baseText!!.styledDocument
    val text = baseText!!.text
    if (text.length > MAX_TEXT_LENGTH_FOR_HIGHLIGHTING) return

    val attributes = SimpleAttributeSet()
    val pattern =
      com.google.re2j.Pattern.compile(
        "([a-zA-Z0-9%.,/*_+-]+)=([a-zA-Z0-9%.,/*_+-]+)",
        com.google.re2j.Pattern.MULTILINE,
      )
    val matcher = pattern.matcher(text)
    while (matcher.find()) {
      val key = matcher.group(1)
      val value = matcher.group(2)
      val keyStart = matcher.start()
      val valueStart = keyStart + key.length + 1
      StyleConstants.setForeground(attributes, ThemeColors.paramKeyForeground())
      document.setCharacterAttributes(keyStart, key.length, attributes, false)
      StyleConstants.setForeground(attributes, ThemeColors.paramValueForeground())
      document.setCharacterAttributes(valueStart, value.length, attributes, false)
    }
  }

  fun textChanged() {
    currentPosition = -1
    updateAll()
  }

  private fun registerShortcuts(container: JComponent?) {
    val target = container ?: return
    val inputMap = target.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
    val actionMap = target.actionMap
    val menuMask = Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx
    bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_F, menuMask), ACTION_FOCUS) {
      focusSearchText()
    }
    bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0), ACTION_NEXT) { findNext() }
    val previousStroke = KeyStroke.getKeyStroke(KeyEvent.VK_F3, KeyEvent.SHIFT_DOWN_MASK)
    bind(inputMap, actionMap, previousStroke, ACTION_PREVIOUS) { findPrevious() }
  }

  private fun bind(
    inputMap: InputMap,
    actionMap: ActionMap,
    keyStroke: KeyStroke,
    name: String,
    action: () -> Unit,
  ) {
    inputMap.put(keyStroke, name)
    actionMap.put(
      name,
      object : AbstractAction() {
        override fun actionPerformed(event: ActionEvent) {
          try {
            action()
          } catch (e: Exception) {
            Logging.errWithStackTrace(e)
          }
        }
      },
    )
  }

  private fun moveToMatch(forward: Boolean) {
    try {
      val textPane = baseText ?: return
      val word = searchText.text
      if (word.isEmpty()) return
      val text = textPane.text
      if (word != previousWord) {
        previousWord = word
        currentPosition = -1
      }
      val found = if (forward) nextIndex(text, word) else previousIndex(text, word)
      if (found < 0) return

      currentPosition = found
      updateSearchText()
      val attributes = SimpleAttributeSet()
      StyleConstants.setBackground(attributes, ThemeColors.searchCurrentHighlight())
      textPane.styledDocument.setCharacterAttributes(found, word.length, attributes, false)
      textPane.caretPosition = found
    } catch (e: Exception) {
      Logging.errWithStackTrace(e)
    }
  }

  private fun nextIndex(text: String, word: String): Int {
    val from = if (currentPosition < 0) 0 else currentPosition + word.length
    val found = text.indexOf(word, from)
    if (found >= 0) return found
    return text.indexOf(word)
  }

  private fun previousIndex(text: String, word: String): Int {
    val from = if (currentPosition < 0) text.length else currentPosition - 1
    val found = text.lastIndexOf(word, from)
    if (found >= 0) return found
    return text.lastIndexOf(word)
  }

  private fun updateAll() {
    coloringClear()
    coloringHTTPText()
    coloringEmphasis()
    updateSearchCount(coloringSearchText())
  }

  private fun updateSearchText() {
    coloringBackgroundClear()
    updateSearchCount(coloringSearchText())
  }

  private fun updateSearchCount(count: Int) {
    var countLabel = i18nString("Not found")
    var countColor = ThemeColors.searchCountNotFoundBackground()
    if (count < 0) {
      countLabel = i18nString("Too Long")
      countColor = ThemeColors.searchCountErrorBackground()
    } else if (count > 0) {
      countLabel = i18nString("%d found").format(count)
      countColor = ThemeColors.searchCountBackground()
    }
    searchCount.background = countColor
    searchCount.foreground = ThemeColors.foregroundOn(countColor)
    searchCount.text = countLabel
    applyCountLabelSize()
  }

  /** 件数ラベルはフォントと表示中の文言から必要な幅を求める。固定サイズだと文字が切れてしまう。 */
  private fun applyCountLabelSize() {
    val metrics = searchCount.getFontMetrics(searchCount.font)
    val samples =
      listOf(
        i18nString("Not found"),
        i18nString("Too Long"),
        i18nString("%d found").format(WIDEST_SAMPLE_COUNT),
        searchCount.text,
      )
    val width = samples.maxOf { metrics.stringWidth(it) } + COUNT_LABEL_PADDING
    val height = metrics.height + COUNT_LABEL_PADDING
    val size = Dimension(width, height)
    if (searchCount.preferredSize == size) return
    searchCount.preferredSize = size
    searchCount.minimumSize = size
    searchCount.maximumSize = Dimension(width, Short.MAX_VALUE.toInt())
    revalidate()
  }

  companion object {
    private val MAX_TEXT_LENGTH_FOR_HIGHLIGHTING = 1_000_000
    private const val COUNT_LABEL_PADDING = 8
    private const val WIDEST_SAMPLE_COUNT = 9999
    private const val ACTION_FOCUS = "packetproxy.search.focus"
    private const val ACTION_NEXT = "packetproxy.search.next"
    private const val ACTION_PREVIOUS = "packetproxy.search.previous"
  }
}
