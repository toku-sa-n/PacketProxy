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

import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import packetproxy.model.CharSets

class CharSetUtility private constructor() {
  private var charSetValue = DEFAULT_CHARSET
  private var autoFlag = false

  fun guessCharSetFromMetatag(rawData: ByteArray): String {
    var data = ""
    val startKeywords = arrayOf("<meta", "&lt;meta")
    val endKeywords = arrayOf("/>", "</meta>", ">", "&#47;&gt;", "&lt;&#47;meta&gt;", "&gt;")
    val charsetStartKeywords = arrayOf("charset=\"", "charset='")
    val charsetEndKeywords = arrayOf("\"", "'")
    val charsetStartKeywordsHTML4 = arrayOf("content=\"", "content='")
    val charsetEndKeywordsHTML4 = arrayOf("\"", "'")
    val charsetStartKeywordsHTML4_2 = arrayOf("charset=")
    val charsetEndKeywordsHTML4_2 = arrayOf(";", "\n")

    try {
      data = String(rawData, StandardCharsets.UTF_8)
    } catch (e: Exception) {
      Logging.errWithStackTrace(e)
    }

    var cur = 0
    while (true) {
      val (metaData, nextCur) = parseDocWithToken(data, startKeywords, endKeywords, cur, false)
      cur = nextCur
      if (cur == -1) return ""

      var (charset, cur2) =
        parseDocWithToken(metaData, charsetStartKeywords, charsetEndKeywords, 0, false)
      if (cur2 != -1) return charset

      val (content, contentCur) =
        parseDocWithToken(metaData, charsetStartKeywordsHTML4, charsetEndKeywordsHTML4, 0, false)
      if (contentCur == -1) continue

      val (html4Charset, html4Cur) =
        parseDocWithToken(content, charsetStartKeywordsHTML4_2, charsetEndKeywordsHTML4_2, 0, true)
      charset = html4Charset
      cur2 = html4Cur
      if (cur2 != -1) return charset
    }
  }

  fun guessCharSetFromHttpHeader(rawData: ByteArray): String {
    val startKeyword = "charset="
    val endKeywords = arrayOf(";", "\n", "\r")
    val headerText = String(rawData, StandardCharsets.ISO_8859_1)
    val headerEnd =
      headerText.indexOf("\r\n\r\n").let { if (it >= 0) it else headerText.indexOf("\n\n") }
    val headers = if (headerEnd >= 0) headerText.substring(0, headerEnd) else headerText
    val contentTypeLine =
      headers.lineSequence().firstOrNull { it.startsWith("Content-Type:", ignoreCase = true) }
        ?: return ""
    val data = contentTypeLine.substringAfter(':').trim().lowercase()
    var start = data.indexOf(startKeyword)
    if (start == -1) return ""

    start += startKeyword.length
    var end = -1
    for (token in endKeywords) {
      end = data.indexOf(token, start)
      if (end != -1) break
    }
    if (end == -1) end = data.length

    return data.substring(start, end).trim()
  }

  fun isAuto(): Boolean = autoFlag

  fun setCharSet(charSet: String?) {
    setCharSet(charSet, false)
  }

  fun setCharSet(charSet: String?, autoStatusUnchanged: Boolean) {
    if (charSet == null) return
    if (AUTO_CHARSET == charSet) {
      autoFlag = true
      return
    }
    if (!autoStatusUnchanged) autoFlag = false

    if (autoFlag) {
      for (key in Charset.availableCharsets().keys) {
        if (key.lowercase() == charSet.lowercase()) {
          this.charSetValue = key
          return
        }
      }
      Logging.log("%s is not supported charset", charSet)
    }

    if (getAvailableCharSetList().contains(charSet)) {
      this.charSetValue = charSet
    } else {
      Logging.log("%s is not supported charset", charSet)
    }
  }

  fun getCharSet(): String = charSetValue

  fun getCharSetForGUIComponent(): String = if (autoFlag) AUTO_CHARSET else charSetValue

  fun setGuessedCharSet(rawData: ByteArray) {
    setCharSet(guessedCharSet(rawData), true)
  }

  fun getAvailableCharSetList(): List<String> {
    val result = mutableListOf<String>()
    try {
      result.add(AUTO_CHARSET)
      for (charset in CharSets.getInstance().queryAll()) {
        result.add(charset.toString())
      }
    } catch (e: Exception) {
      Logging.errWithStackTrace(e)
    }
    return result
  }

  private fun parseDocWithToken(
    data: String,
    startToken: Array<String>,
    endToken: Array<String>,
    current: Int,
    allowEOL: Boolean,
  ): Pair<String, Int> {
    var start = data.length
    var startIndex = -1
    var endIndex = -1
    for (index in startToken.indices) {
      val position = data.indexOf(startToken[index], current)
      if (position == -1) continue
      if (position < start) {
        start = position
        startIndex = index
      }
    }
    if (data.length == start) return Pair("", -1)

    val startAfterToken = start + startToken[startIndex].length
    var end = data.length
    for (index in endToken.indices) {
      val position = data.indexOf(endToken[index], startAfterToken)
      if (position == -1) continue
      if (position < end) {
        end = position
        endIndex = index
      }
    }
    if (data.length == end && !allowEOL) return Pair("", -1)

    val metaData = data.substring(startAfterToken, end)
    if (endIndex in endToken.indices) end += endToken[endIndex].length

    return Pair(metaData, end)
  }

  private fun guessedCharSet(rawData: ByteArray): String {
    var charset = guessCharSetFromHttpHeader(rawData)
    if (charset.isNotEmpty()) return charset

    charset = guessCharSetFromMetatag(rawData)
    if (charset.isNotEmpty()) return charset

    return DEFAULT_CHARSET
  }

  companion object {
    private const val DEFAULT_CHARSET = "UTF-8"
    private const val AUTO_CHARSET = "AUTO"
    private var instance: CharSetUtility? = null

    @JvmStatic
    fun getInstance(): CharSetUtility {
      if (instance == null) {
        instance = CharSetUtility()
        if (!instance!!.getAvailableCharSetList().contains(DEFAULT_CHARSET)) {
          instance!!.charSetValue = instance!!.getAvailableCharSetList()[0]
        }
      }
      return instance!!
    }
  }
}
