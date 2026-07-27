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
package packetproxy.gui

import java.awt.BorderLayout
import java.awt.Color
import java.awt.event.KeyEvent
import java.awt.event.KeyListener
import java.awt.event.MouseEvent
import java.awt.event.MouseListener
import java.util.Arrays
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.JTextPane
import javax.swing.text.MutableAttributeSet
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.Binary
import packetproxy.common.FontManager
import packetproxy.common.StringUtils
import packetproxy.util.Logging.errWithStackTrace

class GUIHistoryBinary : GUIHistoryPanel(), ExtendedTextPane.DataChangedListener {

  private val TRIMMING_SIZE = 100000
  private val DEFAULT_SHOW_SIZE = 2000

  private val hexText: BinaryTextPane
  private val asciiText: JTextPane
  private val searchText: JTextField
  private val boxPanel: JComponent
  private val panel: JComponent

  private var showAll = false
  private var parentTabs: TabSet? = null
  private var data: ByteArray? = null

  override fun getTextPane(): JTextPane = hexText

  init {
    hexText = BinaryTextPane()
    hexText.addDataChangedListener(this)
    hexText.font = FontManager.getInstance().getFont()
    hexText.addMouseListener(
      object : MouseListener {
        override fun mouseClicked(e: MouseEvent) {
          if (showAll) return
          setData(data!!, false)
        }

        override fun mouseEntered(e: MouseEvent) = Unit

        override fun mouseExited(e: MouseEvent) = Unit

        override fun mousePressed(e: MouseEvent) = Unit

        override fun mouseReleased(e: MouseEvent) {
          val positionStart = hexText.selectionStart
          val positionEnd = hexText.selectionEnd
          if (positionStart == positionEnd) return
          coloringSearchBinary()
          highlightFromHex(positionStart, positionEnd, Color.CYAN)
        }
      }
    )
    hexText.addKeyListener(
      object : KeyListener {
        override fun keyPressed(e: KeyEvent) = Unit

        override fun keyReleased(e: KeyEvent) {
          val str = hexText.text
          try {
            val caretPosition = hexText.caretPosition
            val b = Binary(Binary.HexString(str))
            if (Arrays.equals(data, b.toByteArray())) return
            data = b.toByteArray()
            hexText.text = b.toHexString(16).toString()
            asciiText.text = b.toAsciiString(16).toString()
            hexText.caretPosition = caretPosition
            coloringSearchBinary()
            callDataChanged(data!!)
          } catch (e: IllegalArgumentException) {
            // ignore
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }

        override fun keyTyped(e: KeyEvent) = Unit
      }
    )
    val scrollpane3 = JScrollPane(hexText)

    asciiText = JTextPane()
    asciiText.font = FontManager.getInstance().getFont()
    asciiText.addMouseListener(
      object : MouseListener {
        override fun mouseClicked(e: MouseEvent) {
          if (showAll) return
          setData(data!!, false)
        }

        override fun mouseEntered(e: MouseEvent) = Unit

        override fun mouseExited(e: MouseEvent) = Unit

        override fun mousePressed(e: MouseEvent) = Unit

        override fun mouseReleased(e: MouseEvent) {
          val positionStart = asciiText.selectionStart
          val positionEnd = asciiText.selectionEnd
          if (positionStart == positionEnd) return
          coloringSearchBinary()
          highlightFromAscii(positionStart, positionEnd, Color.CYAN)
        }
      }
    )
    val scrollpane4 = JScrollPane(asciiText)
    scrollpane4.verticalScrollBar.model = scrollpane3.verticalScrollBar.model

    searchText = JTextField()
    searchText.font = FontManager.getInstance().getFont()
    searchText.addKeyListener(
      object : KeyListener {
        override fun keyReleased(e: KeyEvent) {
          coloringSearchBinary()
        }

        override fun keyTyped(e: KeyEvent) = Unit

        override fun keyPressed(e: KeyEvent) = Unit
      }
    )

    boxPanel =
      JPanel().apply {
        add(scrollpane3)
        add(scrollpane4)
        layout = BoxLayout(this, BoxLayout.X_AXIS)
      }
    panel =
      JPanel(BorderLayout()).apply {
        add(boxPanel, BorderLayout.CENTER)
        add(searchText, BorderLayout.SOUTH)
      }
  }

  fun createPanel(): JComponent = panel

  override fun setData(data: ByteArray) {
    setData(data, true)
  }

  private fun setData(data: ByteArray, trimming: Boolean) {
    try {
      hexText.font = FontManager.getInstance().getFont()
      asciiText.font = FontManager.getInstance().getFont()
      searchText.font = FontManager.getInstance().getFont()
      hexText.setData(data, false)
      this.data = data
      // データが多いと遅いので長いデータをトリミングする
      if (trimming && data.size > TRIMMING_SIZE) {
        showAll = false
        val head = ArrayUtils.subarray(data, 0, DEFAULT_SHOW_SIZE)
        val b = Binary(head)
        hexText.text =
          "********************\n  This data is too long.\n  If you want to show all message, please click this panel\n********************\n\n\n\n\n\n" +
            b.toHexString(16).toString()
        asciiText.text =
          "********************\n  This data is too long.\n  If you want to show all message, please click this panel\n********************\n\n\n\n\n\n" +
            b.toAsciiString(16).toString()
      } else {
        showAll = true
        val b = Binary(data)
        hexText.text = b.toHexString(16).toString()
        asciiText.text = b.toAsciiString(16).toString()
      }
      hexText.caretPosition = 0
      asciiText.caretPosition = 0
      coloringSearchBinary()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun getData(): ByteArray = data ?: ByteArray(0)

  /** @return search_stringを見つけた回数 */
  fun coloringSearchBinary(): Int {
    val str = hexText.text
    if (str.length > 1000000) {
      // errWithStackTrace omitted: too long string, skipping highlight
      return -1
    }

    // 検索用のバイト列を構築
    val searchString = searchText.text.replace(" ", "")
    return try {
      val searchBytes = StringUtils.hexToByte(searchString.toByteArray())
      coloringSearchBinary(searchBytes)
    } catch (e: Exception) {
      coloringSearchBinary(searchText.text.toByteArray())
    }
  }

  private fun coloringSearchBinary(searchBytes: ByteArray): Int {
    val str = hexText.text
    // 色を元に戻す
    resetHighlight()
    if (str.isEmpty() || searchBytes.isEmpty()) return 0

    // 色を変える
    var cnt = 0
    var start = 0
    while (StringUtils.binaryFind(data!!, searchBytes, start).also { start = it } >= 0) {
      cnt++
      val end = start + searchBytes.size
      highlightFromAscii(start + start / 16, end + end / 16, Color.YELLOW)
      start += searchBytes.size
    }
    return cnt
  }

  private fun resetHighlight() {
    val attributes: MutableAttributeSet = SimpleAttributeSet()
    StyleConstants.setBackground(attributes, Color.WHITE)
    hexText.styledDocument.setCharacterAttributes(0, hexText.text.length, attributes, false)
    asciiText.styledDocument.setCharacterAttributes(0, asciiText.text.length, attributes, false)
  }

  private fun highlightFromHex(hexStart: Int, hexEnd: Int, color: Color) {
    if (hexStart == hexEnd) return
    var start = hexStart
    var end = hexEnd
    if (end < start) {
      val temp = end
      end = start
      start = temp
    }
    val attributes: MutableAttributeSet = SimpleAttributeSet()
    StyleConstants.setBackground(attributes, color)

    hexText.styledDocument.setCharacterAttributes(start, end - start, attributes, false)

    val asciiStart = toAsciiPos(start)
    val asciiEnd = toAsciiPos(end) + 1
    asciiText.styledDocument.setCharacterAttributes(
      asciiStart,
      asciiEnd - asciiStart,
      attributes,
      false,
    )
  }

  private fun highlightFromAscii(asciiStart: Int, asciiEnd: Int, color: Color) {
    if (asciiStart == asciiEnd) return
    var start = asciiStart
    var end = asciiEnd
    if (end < start) {
      val temp = end
      end = start
      start = temp
    }
    highlightFromHex(toHexPos(start), toHexPos(end) - 1, color)
  }

  // hexは1バイト毎にスペース, 両方とも16バイト毎に\n
  private fun toHexPos(pos: Int): Int {
    val y = pos / (16 + 1)
    val x = (pos - y * (16 + 1)) * 3
    return y * (16 * 3 + 1) + x
  }

  private fun toAsciiPos(pos: Int): Int {
    val y = pos / (16 * 3 + 1)
    val x = (pos - y * (16 * 3 + 1)) / 3
    return y * (16 + 1) + x
  }

  override fun setParentTabs(parentTabs: TabSet) {
    this.parentTabs = parentTabs
  }

  override fun getParentSend(): JButton? = parentTabs?.parentSend

  override fun dataChanged(data: ByteArray) = Unit
}
