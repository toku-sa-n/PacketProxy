/*
 * Copyright 2022 DeNA Co., Ltd.
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

package packetproxy.quic.value.frame

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class AckFrameTest {

  @Test
  fun シンプルなbyteArrayをparseできること() {
    val test = Hex.decodeHex("0200030000".toCharArray())
    val ackFrame = AckFrame.parse(test)
    assertEquals(0, ackFrame.largestAcknowledged)
    assertEquals(3, ackFrame.ackDelay)
    assertEquals(0, ackFrame.ackRangeCount)
    assertEquals(0, ackFrame.firstAckRange)
    Assertions.assertEquals(0, ackFrame.ackRanges.size())
  }

  @Test
  fun ackRangeがあるbyteArrayをparseできること() {
    val test = Hex.decodeHex("020a0001000105".toCharArray())
    val ackFrame = AckFrame.parse(test)
    assertEquals(10, ackFrame.largestAcknowledged)
    assertEquals(0, ackFrame.firstAckRange)
    assertEquals(1, ackFrame.ackRangeCount)
    Assertions.assertEquals(1, ackFrame.ackRanges.get(0).gap)
    Assertions.assertEquals(5, ackFrame.ackRanges.get(0).ackRangeLength)
  }

  @Test
  fun parseしてgetBytesすると元に戻ること() {
    val test = Hex.decodeHex("0200030000".toCharArray())
    val ackFrame = AckFrame.parse(test)
    val test2 = ackFrame.getBytes()
    assertArrayEquals(test, test2)
  }

  @Test
  fun rangeありのbyteをparseしてgetBytesすると元に戻ること() {
    val test = Hex.decodeHex("020a0001000105".toCharArray())
    val ackFrame = AckFrame.parse(test)
    val test2 = ackFrame.getBytes()
    assertArrayEquals(test, test2)
  }

  @Test
  fun ackRangeがあるbyteArray2つが等しくなること() {
    val test1 = Hex.decodeHex("020a0001000105".toCharArray())
    val test2 = Hex.decodeHex("020a0001000105".toCharArray())
    val ackFrame1 = AckFrame.parse(test1)
    val ackFrame2 = AckFrame.parse(test2)
    assertThat(ackFrame1).isEqualTo(ackFrame2)
  }
}
