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

import java.awt.Component
import java.awt.Dimension
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import javax.swing.BoxLayout
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import org.apache.commons.codec.binary.Hex
import packetproxy.common.Binary
import packetproxy.common.StringUtils
import packetproxy.common.i18nString
import packetproxy.common.i18nStringArray
import packetproxy.util.errWithStackTrace

class GUIHexCalc {
  private lateinit var intBefore: JTextField
  private lateinit var intHex: JTextField
  private lateinit var strBefore: JTextField
  private lateinit var strHex: JTextField
  private lateinit var endianBox: JComboBox<String>
  private lateinit var intPanel: JComponent
  private lateinit var strPanel: JComponent
  private val mainPanel =
    JPanel().apply {
      background = ThemeColors.panelBackground()
      layout = BoxLayout(this, BoxLayout.Y_AXIS)
      alignmentX = Component.LEFT_ALIGNMENT
    }

  init {
    createIntPanel()
    createStrPanel()
    mainPanel.add(intPanel)
    mainPanel.add(strPanel)
  }

  fun create(): JComponent = mainPanel

  private fun createIntPanel() {
    intBefore =
      JTextField().apply {
        addKeyListener(
          object : KeyAdapter() {
            override fun keyReleased(event: KeyEvent) = intToHexTranslation()
          }
        )
      }
    intHex =
      JTextField().apply {
        addKeyListener(
          object : KeyAdapter() {
            override fun keyReleased(event: KeyEvent) {
              try {
                hexToIntTranslation()
              } catch (exception: Exception) {
                errWithStackTrace(exception)
              }
            }
          }
        )
      }
    endianBox =
      JComboBox(i18nStringArray("Little Endian", "Big Endian")).apply {
        addActionListener { intToHexTranslation() }
      }
    val label =
      JLabel(i18nString("Integer <-> Hex")).apply {
        horizontalAlignment = JLabel.CENTER
        maximumSize = Dimension(100, maximumSize.height)
      }
    intPanel =
      JPanel().apply {
        background = ThemeColors.panelBackground()
        layout = BoxLayout(this, BoxLayout.X_AXIS)
        add(label)
        endianBox.maximumSize = Dimension(100, label.maximumSize.height * 2)
        add(endianBox)
        intBefore.maximumSize = Dimension(300, label.maximumSize.height * 2)
        add(intBefore)
        intHex.maximumSize = Dimension(400, label.maximumSize.height * 2)
        add(intHex)
        maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
      }
  }

  private fun createStrPanel() {
    strBefore =
      JTextField().apply {
        addKeyListener(
          object : KeyAdapter() {
            override fun keyReleased(event: KeyEvent) = strToHexTranslation()
          }
        )
      }
    strHex =
      JTextField().apply {
        addKeyListener(
          object : KeyAdapter() {
            override fun keyReleased(event: KeyEvent) {
              try {
                hexToStrTranslation()
              } catch (exception: Exception) {
                errWithStackTrace(exception)
              }
            }
          }
        )
      }
    val label =
      JLabel(i18nString("String <-> Hex")).apply {
        horizontalAlignment = JLabel.CENTER
        maximumSize = Dimension(100, maximumSize.height)
      }
    strPanel =
      JPanel().apply {
        background = ThemeColors.panelBackground()
        layout = BoxLayout(this, BoxLayout.X_AXIS)
        add(label)
        strBefore.maximumSize = Dimension(400, label.maximumSize.height * 2)
        add(strBefore)
        strHex.maximumSize = Dimension(400, label.maximumSize.height * 2)
        add(strHex)
        maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
      }
  }

  private fun strToHexTranslation() {
    strHex.text = Hex.encodeHexString(strBefore.text.toByteArray())
  }

  private fun intToHexTranslation() {
    if (intBefore.text.isEmpty()) {
      clearInputError(intBefore)
      intHex.text = ""
      return
    }
    var value = intBefore.text.trim().toIntOrNull()
    if (value == null) {
      showInputError(intBefore, i18nString("Not a valid integer"))
      return
    }
    clearInputError(intBefore)
    intHex.text = StringUtils.intToHex(value, isLittleEndian())
  }

  private fun hexToIntTranslation() {
    if (intHex.text.isEmpty()) {
      clearInputError(intHex)
      intBefore.text = ""
      return
    }
    try {
      intBefore.text = Binary(Binary.HexString(intHex.text)).toInt(isLittleEndian()).toString()
      clearInputError(intHex)
    } catch (_: IllegalArgumentException) {
      showInputError(intHex, i18nString("Not a valid hex string"))
    }
  }

  private fun hexToStrTranslation() {
    if (strHex.text.isEmpty()) {
      clearInputError(strHex)
      strBefore.text = ""
      return
    }
    try {
      strBefore.text = Binary(Binary.HexString(strHex.text)).toAsciiString().toString()
      clearInputError(strHex)
    } catch (_: IllegalArgumentException) {
      showInputError(strHex, i18nString("Not a valid hex string"))
    }
  }

  private fun isLittleEndian(): Boolean = endianBox.selectedItem == i18nString("Little Endian")

  private fun showInputError(field: JTextField, message: String) {
    field.putClientProperty(OUTLINE_CLIENT_PROPERTY, "error")
    field.toolTipText = message
    field.repaint()
  }

  private fun clearInputError(field: JTextField) {
    field.putClientProperty(OUTLINE_CLIENT_PROPERTY, null)
    field.toolTipText = null
    field.repaint()
  }

  companion object {
    // FlatLafが赤い枠線を描画するためのプロパティ
    private const val OUTLINE_CLIENT_PROPERTY = "JComponent.outline"
  }
}
