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
import org.apache.commons.codec.binary.Hex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PingFrameHandlingTest {
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
  fun pingIsAnsweredLocallyWithAck() {
    val fm = FrameManager()
    fm.write(Hex.decodeHex("0000080600000000001122334455667788".toCharArray()))

    assertTrue(fm.readControlFrames().isEmpty())

    val reply = readAvailable(fm.getFlowControlledInputStream())
    assertArrayEquals(Hex.decodeHex("0000080601000000001122334455667788".toCharArray()), reply)
  }

  @Test
  @Throws(Exception::class)
  fun pingAckIsDropped() {
    val fm = FrameManager()
    fm.write(Hex.decodeHex("0000080601000000009988776655443322".toCharArray()))

    assertTrue(fm.readControlFrames().isEmpty())
    assertEquals(0, fm.getFlowControlledInputStream().available())
  }
}
