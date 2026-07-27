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
package packetproxy.common

import java.awt.Font
import java.util.Locale
import javax.swing.JComponent
import org.apache.commons.collections4.keyvalue.MultiKey
import org.apache.commons.collections4.map.MultiKeyMap
import packetproxy.model.ConfigInteger
import packetproxy.model.ConfigString

class FontManager private constructor() {
  private val configUIFontName = ConfigString("UIFontName")
  private val configUIFontSize = ConfigInteger("UIFontSize")
  private val configFontName = ConfigString("FontName")
  private val configFontSize = ConfigInteger("FontSize")

  private lateinit var storedUIFont: Font
  private lateinit var storedUICaptionFont: Font
  private lateinit var storedFont: Font

  private val defaultFonts =
    MultiKeyMap<String, LocaleFontStyles>().apply {
      put(
        MultiKey("Windows", Locale.JAPAN.language),
        LocaleFontStyles(FontStyle("SansSerif", 13), FontStyle("ＭＳ ゴシック", 13)),
      )
      put(
        MultiKey("Windows", Locale.ENGLISH.language),
        LocaleFontStyles(FontStyle("SansSerif", 12), FontStyle("Monospaced", 12)),
      )
      put(
        MultiKey("Mac", Locale.JAPAN.language),
        LocaleFontStyles(FontStyle("SansSerif", 12), FontStyle("Monospaced", 12)),
      )
      put(
        MultiKey("Mac", Locale.ENGLISH.language),
        LocaleFontStyles(FontStyle("SansSerif", 12), FontStyle("Monospaced", 12)),
      )
      put(
        MultiKey("Default", Locale.ENGLISH.language),
        LocaleFontStyles(FontStyle("SansSerif", 12), FontStyle("Monospaced", 12)),
      )
      put(
        MultiKey("Default", Locale.JAPAN.language),
        LocaleFontStyles(FontStyle("SansSerif", 12), FontStyle("Monospaced", 12)),
      )
    }

  init {
    createUIFont()
    createFont()
  }

  fun getFont(): Font = storedFont

  fun getUIFont(): Font = storedUIFont

  fun getUIFontHeight(comp: JComponent): Int = comp.getFontMetrics(storedUIFont).height

  fun getUICaptionFont(): Font = storedUICaptionFont

  @Throws(Exception::class)
  fun setUIFont(font: Font) {
    configUIFontName.setString(font.getName())
    configUIFontSize.setInteger(font.size)
    createUIFont()
  }

  @Throws(Exception::class)
  fun setFont(font: Font) {
    configFontName.setString(font.getName())
    configFontSize.setInteger(font.size)
    createFont()
  }

  @Throws(Exception::class)
  fun restoreUIFont() {
    val lfs = getLocaleFontStyles()
    configUIFontName.setString(lfs.uiFont.fontName)
    configUIFontSize.setInteger(lfs.uiFont.fontSize)
    createUIFont()
  }

  @Throws(Exception::class)
  fun restoreFont() {
    val lfs = getLocaleFontStyles()
    configFontName.setString(lfs.font.fontName)
    configFontSize.setInteger(lfs.font.fontSize)
    createFont()
  }

  private fun getLocaleFontStyles(): LocaleFontStyles {
    var os = "Default"
    if (Utils.isWindows()) {
      os = "Windows"
    } else if (Utils.isMac()) {
      os = "Mac"
    }
    var lang = "en"
    if (I18nString.locale.language == "ja") {
      lang = "ja"
    }
    return defaultFonts[os, lang]!!
  }

  @Throws(Exception::class)
  private fun createUIFont() {
    val lfs = getLocaleFontStyles()

    var uiFontName = configUIFontName.getString()
    if (uiFontName.isEmpty()) {
      uiFontName = lfs.uiFont.fontName
      configUIFontName.setString(uiFontName)
    }

    var uiFontSize = configUIFontSize.getInteger()
    if (uiFontSize == 0) {
      uiFontSize = lfs.uiFont.fontSize
      configUIFontSize.setInteger(uiFontSize)
    }

    storedUIFont = Font(uiFontName, Font.PLAIN, uiFontSize)
    storedUICaptionFont = Font(uiFontName, Font.BOLD, uiFontSize + 2)
  }

  @Throws(Exception::class)
  private fun createFont() {
    val lfs = getLocaleFontStyles()

    var fontName = configFontName.getString()
    if (fontName.isEmpty()) {
      fontName = lfs.font.fontName
      configFontName.setString(fontName)
    }

    var fontSize = configFontSize.getInteger()
    if (fontSize == 0) {
      fontSize = lfs.font.fontSize
      configFontSize.setInteger(fontSize)
    }

    storedFont = Font(fontName, Font.PLAIN, fontSize)
  }

  private class FontStyle(val fontName: String, val fontSize: Int)

  private class LocaleFontStyles(val uiFont: FontStyle, val font: FontStyle)

  companion object {
    private var instance: FontManager? = null

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): FontManager {
      if (instance == null) {
        instance = FontManager()
      }
      return instance!!
    }
  }
}
