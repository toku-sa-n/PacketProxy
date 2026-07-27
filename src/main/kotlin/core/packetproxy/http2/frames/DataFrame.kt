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
package packetproxy.http2.frames

import java.io.ByteArrayOutputStream
import org.apache.commons.lang3.ArrayUtils
import packetproxy.http.Http

class DataFrame : Frame {
  constructor(flags: Int, streamId: Int, payload: ByteArray) : super(TYPE, flags, streamId, payload)

  @Throws(Exception::class)
  constructor(frame: Frame) : super(frame) {
    parsePayload()
  }

  @Throws(Exception::class)
  constructor(data: ByteArray) : super(data) {
    parsePayload()
  }

  @Throws(Exception::class)
  constructor(http: Http) : super() {
    val headers = http.header
    streamId = headers.getValue("X-PacketProxy-HTTP2-Stream-Id").orElse("0").toInt()
    flags =
      if (TYPE.ordinal == headers.getValue("X-PacketProxy-HTTP2-Type").orElse("0").toInt()) {
        headers.getValue("X-PacketProxy-HTTP2-Flags").orElse("1").toInt()
      } else {
        FLAG_END_STREAM.toInt()
      }
    payload = http.body
    origPayload = http.body
    extra = byteArrayOf()
    type = TYPE
    length = payload.size
  }

  @Throws(Exception::class)
  private fun parsePayload() {
    if ((flags and FLAG_PADDED.toInt()) > 0) {
      val padLen = payload[0].toInt() and 0xff
      payload = ArrayUtils.subarray(payload, 1, payload.size - padLen)
      flags = flags and FLAG_PADDED.toInt().inv()
    }
  }

  @Throws(Exception::class) override fun toByteArrayWithoutExtra(): ByteArray = toByteArray()

  @Throws(Exception::class)
  fun getHttp(): ByteArray {
    val baos = ByteArrayOutputStream()
    baos.write("HTTP/2 200 OK\r\n".toByteArray())
    baos.write("X-PacketProxy-HTTP2-Type: ${TYPE.ordinal}\r\n".toByteArray())
    baos.write("X-PacketProxy-HTTP2-Stream-Id: $streamId\r\n".toByteArray())
    baos.write("X-PacketProxy-HTTP2-Flags: $flags\r\n".toByteArray())
    baos.write("\r\n".toByteArray())
    baos.write(payload)
    return baos.toByteArray()
  }

  override fun toString(): String = super.toString()

  companion object {
    @JvmField val TYPE: Type = Type.DATA
    @JvmField val FLAG_END_STREAM: Byte = 0x01
    @JvmField val FLAG_PADDED: Byte = 0x08
  }
}
