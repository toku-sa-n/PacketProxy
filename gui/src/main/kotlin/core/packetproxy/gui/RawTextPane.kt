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

import java.awt.Color
import java.awt.Toolkit
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.Charset
import java.util.Base64
import javax.swing.JMenuItem
import javax.swing.JPopupMenu
import org.apache.commons.lang3.StringEscapeUtils
import org.apache.commons.lang3.StringUtils
import packetproxy.common.*
import packetproxy.common.FontManager
import packetproxy.common.Range
import packetproxy.common.Utils
import packetproxy.model.Packet
import packetproxy.util.CharSetUtility
import packetproxy.util.PacketProxyUtility
import packetproxy.util.errWithStackTrace

class RawTextPane(
  private val owner: GUIMain,
  fontManager: FontManager,
  charSetUtility: CharSetUtility,
  packetProxyUtility: PacketProxyUtility,
) : ExtendedTextPane(fontManager, charSetUtility, packetProxyUtility) {
  interface DataChangedListener : ExtendedTextPane.DataChangedListener

  init {
    addKeyListener(
      object : KeyAdapter() {
        override fun keyPressed(event: KeyEvent) {
          if (Toolkit.getDefaultToolkit().menuShortcutKeyMask and event.modifiers == 0) return
          when (event.keyCode) {
            KeyEvent.VK_Z -> {
              if (event.isShiftDown) {
                if (undo_manager.canRedo()) undo_manager.redo()
              } else if (undo_manager.canUndo()) {
                undo_manager.undo()
              }
              event.consume()
            }
            KeyEvent.VK_Y -> {
              if (undo_manager.canRedo()) undo_manager.redo()
              event.consume()
            }
          }
        }
      }
    )
    addMouseListener(
      object : MouseAdapter() {
        override fun mouseReleased(event: MouseEvent) {
          if (Utils.isWindows() && event.isPopupTrigger)
            popupMenu.show(event.component, event.x, event.y)
        }

        override fun mousePressed(event: MouseEvent) {
          if (event.isPopupTrigger) popupMenu.show(event.component, event.x, event.y)
        }
      }
    )
  }

  override fun prepareTextForCopy(selected: String): String = stripTrailingNewlines(selected)

  override fun setEditable(editable: Boolean) {
    super.setEditable(editable)
    if (!editable) background = Color.WHITE
  }

  @Throws(Exception::class)
  override fun setData(data: ByteArray) {
    init_flg = true
    fin_flg = true
    init_count = 0
    prev_text_panel = ""
    raw_data.reset(data)
    if (charSetUtility.isAuto()) charSetUtility.setGuessedCharSet(getData())
    super.setText(String(data, selectedCharset()))
    undo_manager.discardAllEdits()
  }

  override fun getData(): ByteArray = raw_data.toByteArray()

  override fun getText(): String = String(raw_data.toByteArray(), Charsets.UTF_8)

  override fun setText(text: String) {
    try {
      fin_flg = true
      init_flg = true
      init_count = 0
      prev_text_panel = ""
      raw_data.reset(text.toByteArray(Charsets.UTF_8))
      super.setText(text)
      undo_manager.discardAllEdits()
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  private val popupMenu: JPopupMenu
    get() {
      val menu = JPopupMenu()
      addVulCheckers(menu)
      menu.addSeparator()
      menu.add(title("Decoders"))
      menu.add(
        menuItem("URL Decoder") {
          URLDecoder.decode(String(selectionBytes(), selectedCharset()), selectedCharset())
        }
      )
      menu.add(
        menuItem("Base64 / Base64url Decoder") {
          val data = selectionBytes()
          val decoder =
            if (data.any { it == '_'.code.toByte() || it == '-'.code.toByte() })
              Base64.getUrlDecoder()
            else Base64.getDecoder()
          String(decoder.decode(data), Charsets.UTF_8)
        }
      )
      menu.add(menuItem("JWT Decoder") { decodeJwt(selectionBytes()) })
      menu.add(
        menuItem("Unicode Unescaper") {
          StringEscapeUtils.unescapeJava(String(selectionBytes(), selectedCharset()))
        }
      )
      menu.addSeparator()
      menu.add(title("Encoders"))
      menu.add(
        menuItem("URL Encoder") {
          URLEncoder.encode(String(selectionBytes(), selectedCharset()), selectedCharset())
        }
      )
      menu.add(
        menuItem("Base64 Encoder") {
          String(Base64.getEncoder().encode(selectionBytes()), Charsets.UTF_8)
        }
      )
      menu.add(
        menuItem("Base64url Encoder") {
          String(Base64.getUrlEncoder().encode(selectionBytes()), Charsets.UTF_8)
        }
      )
      menu.add(menuItem("JWT Encoder") { encodeJwt(selectionBytes()) })
      menu.add(
        menuItem("Unicode Escaper") {
          String(selectionBytes(), selectedCharset()).toCharArray().joinToString("") {
            "\\u%04X".format(it.code)
          }
        }
      )
      return menu
    }

  private fun addVulCheckers(menu: JPopupMenu) {
    menu.add(title("VulCheck Helpers"))
    for (name in owner.coreServices.vulCheckerManager.getAllVulCheckers().keys) {
      val checker = owner.coreServices.vulCheckerManager.createInstance(name) ?: continue
      menu.add(
        JMenuItem(checker.getName()).apply {
          addActionListener {
            try {
              val range = Range.of(selectionStart, selectionEnd)
              val packet: Packet = owner.getGuiHistory().getGuiPacket().getPacket()
              owner
                .getGuiVulCheckHelper()
                .addVulCheck(checker, packet.getOneShotPacket(getData()), range)
            } catch (exception: Exception) {
              errWithStackTrace(exception)
            }
          }
        }
      )
    }
  }

  private fun title(value: String) =
    JMenuItem(i18nString(value)).apply {
      font = fontManager.getUICaptionFont()
      isEnabled = false
    }

  private fun menuItem(name: String, transform: () -> String) =
    JMenuItem(i18nString(name)).apply {
      addActionListener {
        try {
          GUIDecoderDialog(owner).apply {
            setData(transform().toByteArray(Charsets.UTF_8))
            showDialog()
          }
        } catch (exception: Exception) {
          errWithStackTrace(exception)
        }
      }
    }

  private fun selectionBytes(): ByteArray {
    if (charSetUtility.isAuto()) charSetUtility.setGuessedCharSet(getData())
    return String(getData(), selectedCharset())
      .substring(selectionStart, selectionEnd)
      .toByteArray(selectedCharset())
  }

  private fun selectedCharset() = Charset.forName(charSetUtility.getCharSet())

  private fun decodeJwt(data: ByteArray): String =
    String(data, selectedCharset()).split(".").joinToString(".") {
      String(Base64.getUrlDecoder().decode(it), Charsets.UTF_8)
    }

  private fun encodeJwt(data: ByteArray): String =
    String(data, selectedCharset()).split(".").joinToString(".") {
      val bytes =
        if (it.firstOrNull() == '{') it.toByteArray(Charsets.UTF_8)
        else "12345678901234567890123456789012".toByteArray(Charsets.UTF_8)
      StringUtils.strip(String(Base64.getUrlEncoder().encode(bytes), Charsets.UTF_8), "=")
    }

  private fun stripTrailingNewlines(value: String): String = value.trimEnd('\n', '\r')
}
