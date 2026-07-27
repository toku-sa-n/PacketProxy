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

import java.nio.charset.StandardCharsets
import org.json.JSONArray
import org.json.JSONObject

class PacketProxyUtility {
  fun prettyFormatJSONInRawData(data: ByteArray): ByteArray {
    return try {
      val string = String(data, StandardCharsets.UTF_8)
      string
        .split("\r\n\r\n")
        .map(::prettyFormatJSON)
        .filter(String::isNotEmpty)
        .joinToString("\n")
        .toByteArray()
    } catch (e: Exception) {
      Logging.errWithStackTrace(e)
      "convert failed".toByteArray()
    }
  }

  fun prettyFormatJSON(data: String): String {
    return try {
      var formattedData = data
      var beginsWithLeftSquareBracket = false
      var begin = formattedData.length
      val end = formattedData.length
      if (formattedData.contains("{")) begin = minOf(begin, formattedData.indexOf('{'))
      if (formattedData.contains("[")) begin = minOf(begin, formattedData.indexOf('['))
      formattedData = formattedData.substring(begin, end)
      if (formattedData.isEmpty()) return ""

      if (formattedData.indexOf('[') == 0) {
        formattedData = "{data:$formattedData}"
        beginsWithLeftSquareBracket = true
      }

      val jsonObject = JSONObject(formattedData)
      if (beginsWithLeftSquareBracket) {
        (jsonObject.get("data") as JSONArray).toString(2)
      } else {
        jsonObject.toString(2)
      }
    } catch (e: Exception) {
      ""
    }
  }

  fun isWindows(): Boolean = OS.indexOf("win") >= 0

  fun isMac(): Boolean = OS.indexOf("mac") >= 0

  fun isUnix(): Boolean = OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0

  fun isBinaryData(data: ByteArray, defaultSize: Int): Boolean {
    var count = 0
    for (index in 0 until minOf(data.size, defaultSize)) {
      if (
        data[index] == 0x09.toByte() || data[index] == 0x0A.toByte() || data[index] == 0x0D.toByte()
      ) {
        continue
      }
      if ((0x00 <= data[index] && data[index] < 0x20) || data[index] == 0x7F.toByte()) {
        count++
      }
    }
    return count > 30
  }

  companion object {
    private val OS = System.getProperty("os.name").lowercase()
    private var instance: PacketProxyUtility? = null

    @JvmStatic
    fun getInstance(): PacketProxyUtility {
      if (instance == null) instance = PacketProxyUtility()
      return instance!!
    }
  }
}
