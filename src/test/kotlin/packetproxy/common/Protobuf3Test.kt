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
package packetproxy.common

import kotlin.test.assertContentEquals
import org.junit.jupiter.api.Test

class Protobuf3Test {
  @Test fun testVarint150() = assertRoundTrip("089601")

  @Test fun testString() = assertRoundTrip("120774657374696e67")

  @Test fun testLong() = assertRoundTrip("090102030405060708")

  @Test
  fun testVarintMinus() = assertRoundTrip("08feffffffffffffffff01107b18ffffffffffffffffff01207b")

  @Test
  fun testComplexUnordered() =
    assertRoundTrip(
      "15c3f548400a410a09e3828fe3819fe3819710d20922105a643bdf4f8df33f2db29defa7c609402a1208011207303830303030301a050dbab126442a0b0801120730383030303030"
    )

  @Test
  fun testComplex() =
    assertRoundTrip(
      "0a410a09e3828fe3819fe3819710d20922105a643bdf4f8df33f2db29defa7c609402a1208011207303830303030301a050dbab126442a0b080112073038303030303015c3f54840"
    )

  @Test fun testManyField() = assertRoundTrip("08011002180320042805600c380740084809500a580b3006")

  @Test
  fun testEncodeDecodeBytes() {
    val bytes = Binary(Binary.HexString("0102030405060708090a0b0c0d0e0f101112")).toByteArray()
    assertContentEquals(bytes, Protobuf3.encodeBytes(Protobuf3.decodeBytes(bytes)))
  }

  @Test
  fun testEncodeDecodeBytes2() {
    for (value in 0..8) assertRoundTrip("22010%01x".format(value))
  }

  private fun assertRoundTrip(data: String) {
    val bytes = Binary(Binary.HexString(data)).toByteArray()
    assertContentEquals(bytes, Protobuf3.encode(Protobuf3.decode(bytes)))
  }
}
