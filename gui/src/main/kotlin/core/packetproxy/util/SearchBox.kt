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

import java.awt.Color
import java.awt.Dimension
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import javax.swing.BoxLayout
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.JTextPane
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import packetproxy.common.FontManager
import packetproxy.common.Range

class SearchBox : JPanel() {
  private var baseText: JTextPane? = null
  private var emphasisArea: Range? = null
  private val searchText = JTextField()
  private val searchCount = JLabel("Not found")

  init {
    searchText.font = FontManager.getInstance().getFont()
    searchText.addKeyListener(
      object : KeyAdapter() {
        private var previousWord: String? = null
        private var currentPosition = 0

        override fun keyReleased(event: KeyEvent) {
          try {
            searchText.font = FontManager.getInstance().getFont()
            updateSearchText()

            if (event.keyChar != '\n') return

            val word = searchText.text
            if (word != previousWord) {
              previousWord = word
              currentPosition = 0
            }
            currentPosition = searchText(currentPosition + word.length, word)
            if (currentPosition < 0 || baseText == null) return

            val document = baseText!!.styledDocument
            val attributes = SimpleAttributeSet()
            StyleConstants.setBackground(attributes, Color.magenta)
            document.setCharacterAttributes(currentPosition, word.length, attributes, false)
            baseText!!.caretPosition = currentPosition
          } catch (e: Exception) {
            Logging.errWithStackTrace(e)
          }
        }
      }
    )
    searchCount.isOpaque = true
    searchCount.preferredSize = Dimension(75, 12)
    searchCount.horizontalAlignment = JLabel.CENTER

    layout = BoxLayout(this, BoxLayout.X_AXIS)
    add(searchText)
    add(searchCount)
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
      StyleConstants.setBackground(attributes, Color.yellow)
      document.setCharacterAttributes(start, searchString.length, attributes, false)
      start += searchString.length
    }
    return count
  }

  fun coloringEmphasis() {
    val area = emphasisArea ?: return
    val document = baseText!!.styledDocument
    val attributes = SimpleAttributeSet()
    StyleConstants.setForeground(attributes, Color(0, 200, 0))
    StyleConstants.setBold(attributes, true)
    val start = area.getPositionStart()
    val end = area.getPositionEnd()
    document.setCharacterAttributes(start, end - start, attributes, false)
  }

  fun coloringClear() {
    val document = baseText!!.styledDocument
    val text = baseText!!.text
    val attributes = SimpleAttributeSet()
    StyleConstants.setForeground(attributes, Color.black)
    StyleConstants.setBackground(attributes, Color.white)
    StyleConstants.setBold(attributes, false)
    document.setCharacterAttributes(0, text.length, attributes, false)
  }

  fun coloringBackgroundClear() {
    val document = baseText!!.styledDocument
    val text = baseText!!.text
    val attributes = SimpleAttributeSet()
    StyleConstants.setBackground(attributes, Color.white)
    document.setCharacterAttributes(0, text.length, attributes, false)
  }

  /** TODO HTTPの構造を解釈して、明らかにパラメータではない所を除外する */
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
      StyleConstants.setForeground(attributes, Color.blue)
      document.setCharacterAttributes(keyStart, key.length, attributes, false)
      StyleConstants.setForeground(attributes, Color.red)
      document.setCharacterAttributes(valueStart, value.length, attributes, false)
    }
  }

  fun textChanged() {
    updateAll()
  }

  private fun searchText(start: Int, word: String): Int {
    val textPane = baseText ?: return 0
    return textPane.text.indexOf(word, start)
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
    var countLabel = "Not found"
    var countColor = Color.GRAY
    if (count < 0) {
      countLabel = "Too Long"
      countColor = Color.RED
    } else if (count > 0) {
      countLabel = "%d found".format(count)
      countColor = Color.YELLOW
    }
    searchCount.background = countColor
    searchCount.text = countLabel
  }

  companion object {
    private const val MAX_TEXT_LENGTH_FOR_HIGHLIGHTING = 1_000_000
  }
}
