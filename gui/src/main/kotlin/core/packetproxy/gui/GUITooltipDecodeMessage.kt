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

import java.net.URLDecoder
import org.apache.commons.codec.binary.Base64

class GUITooltipDecodeMessage(private val rawData: ByteArray) {
  private val original = String(rawData, Charsets.UTF_8)
  private var decoded: String? = null

  fun decodeMessage(): String {
    if (isURLEncodedText()) {
      decodeURLEncoding()
    } else if (isBase64Text()) {
      decodeBase64()
    } else {
      return original
    }
    return decoded ?: original
  }

  private fun decodeURLEncoding() {
    decoded =
      try {
        URLDecoder.decode(original, Charsets.UTF_8)
      } catch (exception: Exception) {
        original
      }
  }

  private fun decodeBase64() {
    decoded =
      try {
        String(Base64.decodeBase64(rawData), Charsets.UTF_8)
      } catch (exception: Exception) {
        original
      }
  }

  private fun isURLEncodedText(): Boolean = original.startsWith("%")

  private fun isBase64Text(): Boolean = original.matches(Regex("^[a-zA-Z0-9+/=]+$"))
}
