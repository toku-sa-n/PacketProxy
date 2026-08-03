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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class LogLineStyleTest {
  @Test
  fun splitLogLineSeparatesTimestampAndMessage() {
    val line = "2026/07/31 16:51:00     hello"
    assertEquals(LogLineStyle.TIMESTAMP_PREFIX_LENGTH, 24)
    val (timestamp, message) = LogLineStyle.splitLogLine(line)
    assertEquals("2026/07/31 16:51:00     ", timestamp)
    assertEquals("hello", message)
  }

  @Test
  fun splitLogLineHandlesMultilineMessage() {
    val indent = " ".repeat(LogLineStyle.TIMESTAMP_PREFIX_LENGTH)
    val line = "2026/07/31 16:51:00     first\n${indent}second"
    val (timestamp, message) = LogLineStyle.splitLogLine(line)
    assertEquals("2026/07/31 16:51:00     ", timestamp)
    assertEquals("first\n${indent}second", message)
  }

  @Test
  fun splitLogLineWithoutTimestampReturnsEmptyPrefix() {
    val line = "short"
    val (timestamp, message) = LogLineStyle.splitLogLine(line)
    assertEquals("", timestamp)
    assertEquals("short", message)
  }

  @Test
  fun colorizeForConsoleDimsTimestamp() {
    val line = "2026/07/31 16:51:00     hello"
    val colored = LogLineStyle.colorizeForConsole(line)
    assertTrue(colored.contains("hello"))
    assertTrue(colored.contains("\u001B["))
    assertFalse(colored.startsWith("2026"))
  }

  @Test
  fun colorizeForConsoleMarksErrorMessage() {
    val line = "2026/07/31 16:51:00     boom"
    val normal = LogLineStyle.colorizeForConsole(line, isError = false)
    val error = LogLineStyle.colorizeForConsole(line, isError = true)
    assertTrue(error.contains("boom"))
    assertTrue(error != normal)
    assertTrue(error.contains("\u001B[0;31;1m") || error.contains("\u001B[31m"))
  }
}
