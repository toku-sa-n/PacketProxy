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
package packetproxy.util

import org.jline.jansi.Ansi
import org.jline.jansi.Ansi.Color.BLACK
import org.jline.jansi.Ansi.Color.RED

/**
 * Helpers for splitting and styling PacketProxy log lines.
 *
 * Log lines are formatted as `"yyyy/MM/dd HH:mm:ss " + message` (see [Logging]). Colors are applied
 * only at display time; stored / Logback messages remain plain text.
 */
object LogLineStyle {
  /** Length of `"yyyy/MM/dd HH:mm:ss"` + five spaces. */
  const val TIMESTAMP_PREFIX_LENGTH = 24

  /**
   * Splits a formatted log line into timestamp prefix and message body.
   *
   * If [line] is shorter than [TIMESTAMP_PREFIX_LENGTH], the whole line is treated as the message
   * and the timestamp is empty.
   */
  fun splitLogLine(line: String): Pair<String, String> {
    if (line.length < TIMESTAMP_PREFIX_LENGTH) {
      return "" to line
    }
    return line.substring(0, TIMESTAMP_PREFIX_LENGTH) to line.substring(TIMESTAMP_PREFIX_LENGTH)
  }

  /**
   * Builds an ANSI-colored console line from a plain log line.
   * - Timestamp is dim gray (`bright black`)
   * - Message body is default color, or red + bold when [isError] is true
   *
   * Multi-line messages: only the first line's leading timestamp is dimmed; continuation lines are
   * left as the body color.
   */
  fun colorizeForConsole(line: String, isError: Boolean = false): String {
    val (timestamp, message) = splitLogLine(line)
    if (timestamp.isEmpty()) {
      return styleMessage(message, isError)
    }

    val ansi = Ansi.ansi().fgBright(BLACK).a(timestamp).reset()
    if (isError) {
      ansi.fg(RED).bold().a(message).reset()
    } else {
      ansi.a(message)
    }
    return ansi.toString()
  }

  private fun styleMessage(message: String, isError: Boolean): String {
    if (!isError) return message
    return Ansi.ansi().fg(RED).bold().a(message).reset().toString()
  }
}
