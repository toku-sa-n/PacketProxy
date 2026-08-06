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
package packetproxy.http3.service.frame

import java.nio.ByteBuffer
import packetproxy.http3.utils.parseVarInt
import packetproxy.http3.value.frame.DataFrame
import packetproxy.http3.value.frame.DummyFrame
import packetproxy.http3.value.frame.Frame
import packetproxy.http3.value.frame.Frames
import packetproxy.http3.value.frame.GreaseFrame
import packetproxy.http3.value.frame.HeadersFrame
import packetproxy.http3.value.frame.RawFrame
import packetproxy.http3.value.frame.SettingsFrame

open class FrameParser {
  companion object {
    private val frameMap: MutableMap<Long, Class<out Frame>> = HashMap()

    init {
      register(DataFrame::class.java)
      register(HeadersFrame::class.java)
      register(SettingsFrame::class.java)
      register(GreaseFrame::class.java)
      register(RawFrame::class.java)
      register(DummyFrame::class.java)
    }

    private fun register(klass: Class<out Frame>) {
      val types = klass.getMethod("supportedTypes").invoke(null) as List<*>
      types.forEach { type -> frameMap[type as Long] = klass }
    }

    @JvmStatic
    @Throws(Exception::class)
    fun parse(bytes: ByteArray): Frames = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    @Throws(Exception::class)
    fun parse(buffer: ByteBuffer): Frames {
      val frames = Frames.emptyList()
      while (buffer.hasRemaining()) {
        val type = getTypeWithoutIncrement(buffer)
        val klass = frameMap[type]
        if (klass == null) {
          frames.add(GreaseFrame.parse(buffer))
        } else {
          frames.add(createInstance(klass, buffer))
        }
      }
      return frames
    }

    @Throws(Exception::class)
    private fun createInstance(klass: Class<out Frame>, buffer: ByteBuffer): Frame =
      klass.getMethod("parse", ByteBuffer::class.java).invoke(null, buffer) as Frame

    private fun getTypeWithoutIncrement(buffer: ByteBuffer): Long {
      val saved = buffer.position()
      val type = parseVarInt(buffer)
      buffer.position(saved)
      return type
    }
  }
}
