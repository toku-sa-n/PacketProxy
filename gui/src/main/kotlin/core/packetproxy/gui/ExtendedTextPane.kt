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

import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.nio.charset.Charset
import java.util.Arrays
import java.util.EventListener
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.event.EventListenerList
import javax.swing.event.UndoableEditEvent
import javax.swing.event.UndoableEditListener
import javax.swing.undo.UndoManager
import packetproxy.common.BinaryBuffer
import packetproxy.common.FontManager
import packetproxy.common.Range
import packetproxy.common.Utils
import packetproxy.util.CharSetUtility
import packetproxy.util.PacketProxyUtility
import packetproxy.util.errWithStackTrace

abstract class ExtendedTextPane(
  protected val fontManager: FontManager,
  protected val charSetUtility: CharSetUtility,
  protected val packetProxyUtility: PacketProxyUtility,
) : PlainTextCopyTextPane() {
  private var data: ByteArray? = null
  private var showAll = false
  private val dataChangedListeners = EventListenerList()

  @JvmField var prev_text_panel = ""

  @JvmField var undo_manager = UndoManager()

  @JvmField var raw_data = BinaryBuffer()

  @JvmField var init_count = 0

  @JvmField var init_flg = false

  @JvmField var fin_flg = false

  init {
    editorKit = WrapEditorKit(ByteArray(0))
    font = fontManager.getFont()
    document.addDocumentListener(
      object : DocumentListener {
        override fun insertUpdate(event: DocumentEvent) {
          try {
            if (init_flg) {
              init_count += event.length
              if (init_count == raw_data.getLengthInUTF8()) {
                init_flg = false
                fin_flg = false
                init_count = 0
                prev_text_panel = event.document.getText(0, event.document.length)
              }
              return
            }
            var inserted = event.document.getText(event.offset, event.length)
            prev_text_panel = event.document.getText(0, event.document.length)
            var before = prev_text_panel.substring(0, event.offset)
            raw_data.insert(before.toByteArray().size, inserted.toByteArray())
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }

        override fun removeUpdate(event: DocumentEvent) {
          try {
            if (fin_flg) {
              fin_flg = false
              return
            }
            var before = prev_text_panel.substring(0, event.offset)
            var removed = prev_text_panel.substring(event.offset, event.offset + event.length)
            prev_text_panel = event.document.getText(0, event.document.length)
            raw_data.remove(before.toByteArray().size, removed.toByteArray().size)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }

        override fun changedUpdate(event: DocumentEvent) {}
      }
    )
    document.addUndoableEditListener(
      UndoableEditListener { event: UndoableEditEvent ->
        if (
          event.edit is DocumentEvent &&
            (event.edit as DocumentEvent).type == DocumentEvent.EventType.CHANGE
        ) {
          return@UndoableEditListener
        }
        undo_manager.addEdit(event.edit)
      }
    )
    addMouseListener(
      object : MouseAdapter() {
        override fun mouseClicked(event: MouseEvent) {
          try {
            if (showAll) {
              return
            }
            setData(data ?: return, false)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }

        override fun mouseReleased(event: MouseEvent) {
          showDecodedTooltipOnSelectedText()
        }
      }
    )
    addKeyListener(
      object : KeyAdapter() {
        override fun keyReleased(event: KeyEvent) {
          if (Arrays.equals(data, getData())) {
            return
          }
          data = getData()
          callDataChanged(data ?: return)
        }

        override fun keyTyped(event: KeyEvent) {
          callDataChanged(getData())
        }
      }
    )
  }

  @Throws(Exception::class)
  fun setData(data: ByteArray, trimming: Boolean) {
    font = fontManager.getFont()
    this.data = data
    if (
      trimming &&
        (data.size > TEXT_TRIMMING_SIZE ||
          (packetProxyUtility.isBinaryData(data, BINARY_TRIMMING_SIZE) &&
            data.size > BINARY_TRIMMING_SIZE))
    ) {
      showAll = false
      var head = data.copyOfRange(0, DEFAULT_SHOW_SIZE)
      if (charSetUtility.isAuto()) {
        charSetUtility.setGuessedCharSet(getData())
      }
      setText(
        "********************\n  This data is too long.\n" +
          "  If you want to show all message, please click this panel\n" +
          "********************\n\n\n\n\n\n" +
          String(head, Charset.forName(charSetUtility.getCharSet()))
      )
    } else {
      showAll = true
      setData(data)
      callDataChanged(data)
    }
    caretPosition = 0
  }

  fun addDataChangedListener(listener: DataChangedListener) {
    dataChangedListeners.add(DataChangedListener::class.java, listener)
  }

  @Throws(Exception::class) abstract fun setData(data: ByteArray)

  abstract fun getData(): ByteArray

  protected fun callDataChanged(data: ByteArray) {
    for (listener in dataChangedListeners.getListeners(DataChangedListener::class.java)) {
      listener.dataChanged(data)
    }
  }

  private fun showDecodedTooltipOnSelectedText() {
    var area = Range.of(selectionStart, selectionEnd)
    if (area.getLength() == 0) {
      return
    }
    var request =
      Utils.getSelectedCharacters(data ?: return, area.getPositionStart(), area.getPositionEnd())
    toolTipText = GUITooltipDecodeMessage(request).decodeMessage()
  }

  interface DataChangedListener : EventListener {
    fun dataChanged(data: ByteArray)
  }

  private companion object {
    const val TEXT_TRIMMING_SIZE = 300000
    const val BINARY_TRIMMING_SIZE = 10000
    const val DEFAULT_SHOW_SIZE = 2000
  }
}
