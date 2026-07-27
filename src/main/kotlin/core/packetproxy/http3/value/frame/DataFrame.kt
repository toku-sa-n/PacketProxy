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
import org.apache.commons.codec.binary.Hex
import packetproxy.http3.utils.parseVarInt
import packetproxy.http3.utils.readSimpleBytes
import packetproxy.quic.value.VariableLengthInteger
import packetproxy.util.Logging.errWithStackTrace

class DataFrame private constructor(frameData: ByteArray) : Frame {
  private val type: Long = TYPE
  private val data: ByteArray = frameData

  override fun getType(): Long = type

  fun getData(): ByteArray = data

  override fun getBytes(): ByteArray {
    val frameStream = ByteArrayOutputStream()
    try {
      frameStream.write(VariableLengthInteger.of(type).bytes)
      frameStream.write(VariableLengthInteger.of(data.size.toLong()).bytes)
      frameStream.write(data)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    return frameStream.toByteArray()
  }

  override fun toString(): String = String.format("DataFrame(data=[%s])", Hex.encodeHexString(data))

  companion object {
    @JvmField val TYPE: Long = 0x00

    @JvmStatic fun supportedTypes(): List<Long> = ImmutableList.of(TYPE)

    @JvmStatic
    fun parse(buffer: ByteBuffer): DataFrame {
      parseVarInt(buffer)
      val frameLength = parseVarInt(buffer)
      val frameData = readSimpleBytes(buffer, frameLength)
      return DataFrame(frameData)
    }

    @JvmStatic fun of(frameData: ByteArray): DataFrame = DataFrame(frameData)
  }
}
