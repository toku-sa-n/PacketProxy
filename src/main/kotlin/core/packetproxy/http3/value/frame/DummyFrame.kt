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
package packetproxy.http3.value.frame

import com.google.common.collect.ImmutableList
import java.io.ByteArrayOutputStream
import packetproxy.quic.value.VariableLengthInteger

class DummyFrame private constructor(private val value: Long) : Frame {
  private val type: Long = TYPE

  override fun getType(): Long = type

  fun getValue(): Long = value

  fun getData(): ByteArray = VariableLengthInteger.of(value).bytes

  @Throws(Exception::class)
  override fun getBytes(): ByteArray {
    val dataFrameStream = ByteArrayOutputStream()
    dataFrameStream.write(VariableLengthInteger.of(type).bytes)
    dataFrameStream.write(VariableLengthInteger.of(value).bytes)
    return dataFrameStream.toByteArray()
  }

  override fun toString(): String = String.format("DummyFrame(value=%d)", value)

  companion object {
    @JvmField val TYPE: Long = 0x33 /* dummy type */

    @JvmStatic fun of(value: Long): DummyFrame = DummyFrame(value)

    @JvmStatic fun supportedTypes(): List<Long> = ImmutableList.of(TYPE)
  }
}
