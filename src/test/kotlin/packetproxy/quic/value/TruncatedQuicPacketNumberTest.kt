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

package packetproxy.quic.value

import org.apache.commons.codec.binary.Hex
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class TruncatedQuicPacketNumberTest {

  @Test
  fun _0() {
    val packetNumber = PacketNumber.of(0)
    val largestAckedPn = PacketNumber.Infinite

    val truncatedPn = TruncatedPacketNumber(packetNumber, largestAckedPn)
    assertEquals(packetNumber, truncatedPn.getPacketNumber(largestAckedPn))
  }

  @Test
  fun _1() {
    val packetNumber = PacketNumber.of(1)
    val largestAckedPn = PacketNumber.of(0)

    val truncatedPn = TruncatedPacketNumber(packetNumber, largestAckedPn)
    assertEquals(packetNumber, truncatedPn.getPacketNumber(largestAckedPn))
  }

  @Test
  fun _255() {
    val packetNumber = PacketNumber.of(255)
    val largestAckedPn = PacketNumber.of(0)

    val truncatedPn = TruncatedPacketNumber(packetNumber, largestAckedPn)
    assertEquals(packetNumber, truncatedPn.getPacketNumber(largestAckedPn))
  }

  @Test
  fun _256() {
    val packetNumber = PacketNumber.of(256)
    val largestAckedPn = PacketNumber.of(0)

    val truncatedPn = TruncatedPacketNumber(packetNumber, largestAckedPn)
    assertEquals(packetNumber, truncatedPn.getPacketNumber(largestAckedPn))
  }

  @Test
  fun _123456789() {
    val packetNumber = PacketNumber.of(123456789)
    val largestAckedPn = PacketNumber.of(0)

    val truncatedPn = TruncatedPacketNumber(packetNumber, largestAckedPn)
    assertEquals(packetNumber, truncatedPn.getPacketNumber(largestAckedPn))
  }

  @Test
  fun _aabbccdd() {
    val packetNumber = PacketNumber.of(0xaabbccddL)
    val largestAckedPn = PacketNumber.of(0)

    val truncatedPn = TruncatedPacketNumber(packetNumber, largestAckedPn)
    assertEquals(packetNumber, truncatedPn.getPacketNumber(largestAckedPn))
  }

  @Test
  fun _aabbccd0() {
    val packetNumber = PacketNumber.of(0xaabbccddL)
    val largestAckedPn = PacketNumber.of(0xaabbccd0L)

    val truncatedPn = TruncatedPacketNumber(packetNumber, largestAckedPn)
    assertEquals(packetNumber, truncatedPn.getPacketNumber(largestAckedPn))
  }

  @Test
  fun rfc1() {
    /*
     * if an endpoint has received an acknowledgment for packet 0xabe8b3 and is sending a packet with a number of 0xac5c02,
     * there are 29,519 (0x734f) outstanding packet numbers. In order to represent at least twice this range (59,038 packets, or 0xe69e), 16 bits are required.
     */
    val packetNumber = PacketNumber.of(0xac5c02)
    val largestAckedPn = PacketNumber.of(0xabe8b3)
    val truncatedPnBytes = Hex.decodeHex("5c02".toCharArray())

    val truncatedPn = TruncatedPacketNumber(packetNumber, largestAckedPn)
    assertArrayEquals(truncatedPnBytes, truncatedPn.bytes)
  }

  @Test
  fun rfc2() {
    /*
     * if the highest successfully authenticated packet had a packet number of 0xa82f30ea, * then a packet containing a 16-bit value of 0x9b32 will be decoded as 0xa82f9b32
     */
    val truncatedPnBytes = Hex.decodeHex("9b32".toCharArray())
    val packetNumber = PacketNumber.of(0xa82f9b32L)
    val largestAckedPn = PacketNumber.of(0xa82f30eaL)

    val truncatedPn1 = TruncatedPacketNumber(truncatedPnBytes)
    val truncatedPn2 = TruncatedPacketNumber(packetNumber, largestAckedPn)
    assertEquals(packetNumber, truncatedPn1.getPacketNumber(largestAckedPn))
    assertEquals(packetNumber, truncatedPn2.getPacketNumber(largestAckedPn))
    assertEquals(truncatedPn1, truncatedPn2)
  }
}
