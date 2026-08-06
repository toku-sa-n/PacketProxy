/*
 * Copyright 2025 DeNA Co., Ltd.
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

/** 画面から入力されたポート番号文字列を検証する */
object PortValidator {
  const val MIN_PORT = 1
  const val MAX_PORT = 65535

  /** 1〜65535のポート番号として解釈できた場合はその値を返す。解釈できない場合はnullを返す */
  fun parse(text: String?): Int? {
    var port = text?.trim()?.toIntOrNull() ?: return null
    if (port !in MIN_PORT..MAX_PORT) {
      return null
    }
    return port
  }

  /** 不正なポート番号が入力されたときに画面へ表示するメッセージを返す */
  fun errorMessage(fieldLabel: String): String =
    i18nString("%s: Port number must be between 1 and 65535", stripTrailingColon(fieldLabel))

  private fun stripTrailingColon(label: String): String = label.trim().removeSuffix(":").trim()
}
