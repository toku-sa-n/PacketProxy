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

package packetproxy.quic.service.ackgenerator

import org.apache.commons.codec.binary.Hex
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import packetproxy.quic.service.framegenerator.AckFrameGenerator

class AckFrameGeneratorTest {

  @Test
  fun 全て受信() {
    val ackFrameGenerator = AckFrameGenerator()

    ackFrameGenerator.received(0)
    ackFrameGenerator.received(1)
    ackFrameGenerator.received(2)
    ackFrameGenerator.received(3)

    val ackFrame = ackFrameGenerator.generateAckFrame()!!
    assertEquals(3, ackFrame.largestAcknowledged)
    assertEquals(3, ackFrame.firstAckRange)
    assertEquals(0, ackFrame.ackRangeCount)
  }

  @Test
  fun 全て受信ただし開始番号が途中() {
    val ackFrameGenerator = AckFrameGenerator()

    ackFrameGenerator.received(5)
    ackFrameGenerator.received(6)
    ackFrameGenerator.received(7)
    ackFrameGenerator.received(8)

    val ackFrame = ackFrameGenerator.generateAckFrame()!!
    assertEquals(8, ackFrame.largestAcknowledged)
    assertEquals(3, ackFrame.firstAckRange)
    assertEquals(0, ackFrame.ackRangeCount)
  }

  @Test
  fun 受信できていないpacketが存在() {
    val ackFrameGenerator = AckFrameGenerator()

    ackFrameGenerator.received(100)

    val ackFrame = ackFrameGenerator.generateAckFrame()!!
    assertEquals(100, ackFrame.largestAcknowledged)
    assertEquals(0, ackFrame.firstAckRange)
    assertEquals(0, ackFrame.ackRangeCount)
  }

  @Test
  fun 受信できていないpacketが複数存在() {
    val ackFrameGenerator = AckFrameGenerator()

    ackFrameGenerator.received(2)
    ackFrameGenerator.received(3)
    ackFrameGenerator.received(4)
    ackFrameGenerator.received(5)
    ackFrameGenerator.received(6)
    ackFrameGenerator.received(7)
    ackFrameGenerator.received(10)

    val ackFrame = ackFrameGenerator.generateAckFrame()!!
    assertEquals(10, ackFrame.largestAcknowledged)
    assertEquals(0, ackFrame.firstAckRange)
    assertEquals(1, ackFrame.ackRangeCount)
    assertEquals(1, ackFrame.ackRanges.get(0).gap)
    assertEquals(5, ackFrame.ackRanges.get(0).ackRangeLength)
  }

  @Test
  fun 最初のpacketを受信した後getBytesできること() {
    val ackFrameGenerator = AckFrameGenerator()
    ackFrameGenerator.received(0)
    val ackFrame = ackFrameGenerator.generateAckFrame()!!

    assertEquals(0, ackFrame.largestAcknowledged)
    assertEquals(0, ackFrame.firstAckRange)
    assertEquals(0, ackFrame.ackRangeCount)
    assertArrayEquals(Hex.decodeHex("0200000000".toCharArray()), ackFrame.getBytes())
  }

  @Test
  fun 相手に受信されるとAckFrameは生成されない() {
    val ackFrameGenerator = AckFrameGenerator()
    ackFrameGenerator.received(2)
    ackFrameGenerator.received(4)
    ackFrameGenerator.received(6)
    val ackFrame = ackFrameGenerator.generateAckFrame()!!
    ackFrameGenerator.confirmedAckFrame(ackFrame)
    val ackFrame2 = ackFrameGenerator.generateAckFrame()

    assertNotNull(ackFrame)
    assertNull(ackFrame2)
  }

  @Test
  fun 相手に受信された後さらに受信すると差分のAckFrameが生成される() {
    val ackFrameGenerator = AckFrameGenerator()
    ackFrameGenerator.received(2)
    ackFrameGenerator.received(4)
    ackFrameGenerator.received(6)
    val ackFrame = ackFrameGenerator.generateAckFrame()!!
    ackFrameGenerator.received(7)
    ackFrameGenerator.received(9)
    ackFrameGenerator.confirmedAckFrame(ackFrame)
    val ackFrame2 = ackFrameGenerator.generateAckFrame()

    assertNotNull(ackFrame)
    assertNotNull(ackFrame2)
    assertEquals(9, ackFrame2!!.largestAcknowledged)
    assertEquals(0, ackFrame2.firstAckRange)
    assertEquals(1, ackFrame2.ackRangeCount)
    assertEquals(0, ackFrame2.ackRanges.get(0).gap)
    assertEquals(0, ackFrame2.ackRanges.get(0).ackRangeLength)
  }
}
