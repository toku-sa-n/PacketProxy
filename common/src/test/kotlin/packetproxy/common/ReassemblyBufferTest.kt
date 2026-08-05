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
package packetproxy.common

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReassemblyBufferTest {
  @Test
  fun discard_keepsUnconsumedTail() {
    val buf = ReassemblyBuffer()
    buf.write("abcdef".toByteArray(), 0, 6)
    assertEquals(6, buf.size())
    buf.discard(2)
    assertTrue(buf.toByteArray().contentEquals("cdef".toByteArray()))
    buf.write("gh".toByteArray(), 0, 2)
    assertTrue(buf.toByteArray().contentEquals("cdefgh".toByteArray()))
  }

  @Test
  fun write_rejectsOverMaxSize() {
    val buf = ReassemblyBuffer(8)
    buf.write("12345678".toByteArray(), 0, 8)
    assertThrows(IllegalStateException::class.java) { buf.write("9".toByteArray(), 0, 1) }
  }
}
