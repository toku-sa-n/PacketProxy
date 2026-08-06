/*
 * Copyright 2019,2023 DeNA Co., Ltd.
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
package packetproxy.websocket

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class WebSocketFrameLengthTest {
  @ParameterizedTest
  @ValueSource(ints = [125, 126, 65535, 65536])
  @Throws(Exception::class)
  fun unmaskedRoundtripAtLengthBoundaries(payloadSize: Int) {
    val payload = ByteArray(payloadSize) { (it % 256).toByte() }
    val frame = WebSocketFrame.of(OpCode.Binary, payload, false)
    val bytes = frame.getBytes()

    assertEquals(bytes.size, WebSocketFrame.checkDelimiter(bytes))

    // Verify RFC6455 length encoding
    val lengthType = bytes[1].toInt() and 0x7f
    when {
      payloadSize < 126 -> assertEquals(payloadSize, lengthType)
      payloadSize < 65536 -> {
        assertEquals(126, lengthType)
        val encoded = ((bytes[2].toInt() and 0xff) shl 8) or (bytes[3].toInt() and 0xff)
        assertEquals(payloadSize, encoded)
      }
      else -> {
        assertEquals(127, lengthType)
        var encoded = 0L
        for (i in 0 until 8) {
          encoded = (encoded shl 8) or (bytes[2 + i].toLong() and 0xffL)
        }
        assertEquals(payloadSize.toLong(), encoded)
      }
    }

    val parsed = WebSocketFrame.parse(bytes)
    assertArrayEquals(payload, parsed.payload)
    assertTrue(!parsed.maskEnabled)
  }
}
