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

import java.io.InputStream
import java.nio.ByteBuffer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import packetproxy.http2.frames.*
import packetproxy.http2.frames.Frame

class FrameManagerStreamIdTest {
  private fun headersFrame(streamId: Int): ByteArray {
    val payload = byteArrayOf(0x82.toByte())
    val bb = ByteBuffer.allocate(9 + payload.size)
    bb.put(0.toByte()).put(0.toByte()).put(payload.size.toByte())
    bb.put(Frame.Type.HEADERS.ordinal.toByte())
    bb.put(0x04.toByte())
    bb.putInt(streamId)
    bb.put(payload)
    return bb.array()
  }

  @Throws(Exception::class)
  private fun readAvailable(`in`: InputStream): ByteArray {
    val n = `in`.available()
    val buf = ByteArray(n)
    var read = 0
    while (read < n) {
      read += `in`.read(buf, read, n - read)
    }
    return buf
  }

  @Test
  @Throws(Exception::class)
  fun outgoingHeadersGetIncreasingServerStreamIds() {
    val serverFm = FrameManager()
    serverFm.setStreamIdRemapper(StreamIdRemapper())

    serverFm.putToFlowControlledQueue(headersFrame(25))
    serverFm.putToFlowControlledQueue(headersFrame(23))

    val out = readAvailable(serverFm.getFlowControlledInputStream())
    val frames = parseFrames(out)

    assertEquals(2, frames.size)
    assertEquals(Frame.Type.HEADERS, frames[0].type)
    assertEquals(Frame.Type.HEADERS, frames[1].type)
    assertEquals(1, frames[0].streamId)
    assertEquals(3, frames[1].streamId)
  }

  @Test
  @Throws(Exception::class)
  fun withoutRemapperStreamIdsUnchanged() {
    val fm = FrameManager()

    fm.putToFlowControlledQueue(headersFrame(25))
    fm.putToFlowControlledQueue(headersFrame(23))

    val out = readAvailable(fm.getFlowControlledInputStream())
    val frames = parseFrames(out)

    assertEquals(25, frames[0].streamId)
    assertEquals(23, frames[1].streamId)
  }
}
