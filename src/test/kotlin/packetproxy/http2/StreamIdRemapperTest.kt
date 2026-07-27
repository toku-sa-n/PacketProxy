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
/*
 * Copyright 2026 DeNA Co., Ltd.
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
package packetproxy.http2

import java.nio.ByteBuffer
import java.util.Arrays
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class StreamIdRemapperTest {
  private fun frame(type: Int, streamId: Int, payloadLen: Int): ByteArray {
    val bb = ByteBuffer.allocate(9 + payloadLen)
    bb.put(((payloadLen ushr 16) and 0xff).toByte())
    bb.put(((payloadLen ushr 8) and 0xff).toByte())
    bb.put((payloadLen and 0xff).toByte())
    bb.put(type.toByte())
    bb.put(0.toByte())
    bb.putInt(streamId)
    bb.put(ByteArray(payloadLen))
    return bb.array()
  }

  private fun streamIdOf(f: ByteArray): Int =
    ((f[5].toInt() and 0x7f) shl 24) or
      ((f[6].toInt() and 0xff) shl 16) or
      ((f[7].toInt() and 0xff) shl 8) or
      (f[8].toInt() and 0xff)

  @Test
  fun allocatesIncreasingServerIdsInSendOrder() {
    val m = StreamIdRemapper()
    assertEquals(1, m.mapClientToServer(25, true))
    assertEquals(1, m.mapClientToServer(25, false))
    assertEquals(3, m.mapClientToServer(23, true))
    assertEquals(3, m.mapClientToServer(23, false))
    assertEquals(25, m.mapServerToClient(1))
    assertEquals(23, m.mapServerToClient(3))
  }

  @Test
  fun dataWithoutAllocationIsIdentity() {
    val m = StreamIdRemapper()
    assertEquals(99, m.mapClientToServer(99, false))
  }

  @Test
  @Throws(Exception::class)
  fun rewriteResponseMapsHeadersAndDataBack() {
    val m = StreamIdRemapper()
    m.mapClientToServer(25, true)
    m.mapClientToServer(23, true)

    val respFor25 = concat(frame(HEADERS, 1, 4), frame(DATA, 1, 8))
    val rewritten = m.rewriteResponseToClient(respFor25)
    assertEquals(25, streamIdOf(rewritten))
    assertEquals(25, streamIdOf(Arrays.copyOfRange(rewritten, 9 + 4, rewritten.size)))

    val respFor23 = frame(HEADERS, 3, 4)
    assertEquals(23, streamIdOf(m.rewriteResponseToClient(respFor23)))
  }

  @Test
  @Throws(Exception::class)
  fun rewriteResponseUnknownIdIsIdentity() {
    val m = StreamIdRemapper()
    val resp = frame(HEADERS, 7, 4)
    assertEquals(7, streamIdOf(m.rewriteResponseToClient(resp)))
  }

  private fun concat(a: ByteArray, b: ByteArray): ByteArray {
    val out = ByteArray(a.size + b.size)
    System.arraycopy(a, 0, out, 0, a.size)
    System.arraycopy(b, 0, out, a.size, b.size)
    return out
  }

  companion object {
    private const val HEADERS = 0x1
    private const val DATA = 0x0
  }
}
