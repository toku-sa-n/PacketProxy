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

import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/* https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16 */
class VariableLengthIntegerTest {

  @Test
  fun smoke() {
    val t = VariableLengthInteger.parse(Hex.decodeHex("800061a8".toCharArray()))
    assertEquals(25000, t.value)
  }

  @Test
  fun parseSingleByte() {
    // "and the single byte 25 decodes to 37"
    val testBytes = Hex.decodeHex("25".toCharArray())
    val vli = VariableLengthInteger.parse(ByteBuffer.wrap(testBytes))

    assertEquals(37, vli.value)
    assertArrayEquals(testBytes, vli.bytes)
  }

  @Test
  fun parseTwoBytes() {
    // "the two byte sequence 7b bd decodes to 15293; "
    val testBytes = Hex.decodeHex("7bbd".toCharArray())
    val vli = VariableLengthInteger.parse(ByteBuffer.wrap(testBytes))

    assertEquals(15293, vli.value)
    assertArrayEquals(testBytes, vli.bytes)
  }

  @Test
  fun parseTwoBytes2() {
    // "(as does the two byte sequence 40 25)"
    val testBytes = Hex.decodeHex("4025".toCharArray())
    val vli = VariableLengthInteger.parse(ByteBuffer.wrap(testBytes))

    assertEquals(37, vli.value)
  }

  @Test
  fun parseFourBytes() {
    // "the four byte sequence 9d 7f 3e 7d decodes to 494878333;"
    val testBytes = Hex.decodeHex("9d7f3e7d".toCharArray())
    val vli = VariableLengthInteger.parse(ByteBuffer.wrap(testBytes))

    assertEquals(494878333, vli.value)
    assertArrayEquals(testBytes, vli.bytes)
  }

  @Test
  fun parseEightBytes() {
    // "the eight byte sequence c2 19 7c 5e ff 14 e8 8c decodes to
    // 151288809941952652;"
    val testBytes = Hex.decodeHex("c2197c5eff14e88c".toCharArray())
    val vli = VariableLengthInteger.parse(ByteBuffer.wrap(testBytes))

    assertEquals(151288809941952652L, vli.value)
    assertArrayEquals(testBytes, vli.bytes)
  }

  @Test
  fun parseExampleBytes() {
    assertEquals(
      0x200000,
      VariableLengthInteger.parse(Hex.decodeHex("80200000".toCharArray())).value,
    )
    /* 2MB */
    assertEquals(
      0x100000,
      VariableLengthInteger.parse(Hex.decodeHex("80100000".toCharArray())).value,
    )
    /* 1MB */
    assertEquals(513, VariableLengthInteger.parse(Hex.decodeHex("4201".toCharArray())).value)
    /* 513 */
    assertEquals(119, VariableLengthInteger.parse(Hex.decodeHex("4077".toCharArray())).value)
    /* 119 */
    assertEquals(6347, VariableLengthInteger.parse(Hex.decodeHex("58cb".toCharArray())).value)
    /* 6347 */
    assertEquals(
      0x3684f228323451e8L,
      VariableLengthInteger.parse(Hex.decodeHex("f684f228323451e8".toCharArray())).value,
    )
    /* 3684f228323451e8 — top bits encode length */
    assertEquals(0, VariableLengthInteger.parse(Hex.decodeHex("00".toCharArray())).value)
    /* 0 */
  }
}
