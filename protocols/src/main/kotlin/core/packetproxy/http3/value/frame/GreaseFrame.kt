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
import java.nio.ByteBuffer
import packetproxy.http3.utils.parseVarInt
import packetproxy.http3.utils.readSimpleBytes
import packetproxy.quic.value.VariableLengthInteger

class GreaseFrame(frameType: Long, frameData: ByteArray) : Frame {
  private val type: Long = frameType
  private val data: ByteArray = frameData

  override fun getType(): Long = type

  fun getData(): ByteArray = data

  @Throws(Exception::class)
  override fun getBytes(): ByteArray {
    val frameStream = ByteArrayOutputStream()
    frameStream.write(VariableLengthInteger.of(type).bytes)
    frameStream.write(VariableLengthInteger.of(data.size.toLong()).bytes)
    frameStream.write(data)
    return frameStream.toByteArray()
  }

  override fun toString(): String =
    String.format("GreaseFrame(type=0x%x,data=[%s])", type, String(data))

  companion object {
    const val GreaseType: Long = 0xDEADBEEFL

    @JvmStatic fun supportedTypes(): List<Long> = ImmutableList.of(GreaseType)

    @JvmStatic fun of(type: Long, bytes: ByteArray): GreaseFrame = GreaseFrame(type, bytes)

    @JvmStatic fun parse(type: Long, bytes: ByteArray): GreaseFrame = of(type, bytes)

    @JvmStatic
    fun parse(buffer: ByteBuffer): GreaseFrame {
      val frameType = parseVarInt(buffer)
      val startOfLength = buffer.position()
      val frameLength = parseVarInt(buffer)
      val frameData: ByteArray =
        if (frameLength > buffer.remaining().toLong()) {
          buffer.position(startOfLength)
          readSimpleBytes(buffer, buffer.remaining().toLong())
        } else {
          readSimpleBytes(buffer, frameLength)
        }
      return GreaseFrame(frameType, frameData)
    }
  }
}
