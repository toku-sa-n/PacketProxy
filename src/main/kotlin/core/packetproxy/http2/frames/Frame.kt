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

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer

open class Frame {
  enum class Type {
    DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION, ALTSVC, Unassigned, ORIGIN,
  }

  var length: Int = 9
  var type: Type = Type.Unassigned
  var flags: Int = 0
  var streamId: Int = 0
  var payload: ByteArray = byteArrayOf()
  var origPayload: ByteArray = byteArrayOf()
  var extra: ByteArray = byteArrayOf()

  @Throws(Exception::class) protected constructor()

  constructor(type: Type, flags: Int, streamId: Int, payload: ByteArray) {
    this.type = type
    this.length = payload.size
    this.flags = flags
    this.streamId = streamId
    this.payload = payload
    this.origPayload = payload
    this.extra = byteArrayOf()
  }

  @Throws(Exception::class)
  constructor(frame: Frame) {
    length = frame.length
    type = frame.type
    flags = frame.flags
    streamId = frame.streamId
    payload = frame.payload
    origPayload = frame.origPayload
    extra = frame.extra
  }

  @Throws(Exception::class)
  constructor(data: ByteArray) {
    val bais = ByteArrayInputStream(data)
    val buffer = ByteArray(128)
    bais.read(buffer, 0, 3)
    length = ((buffer[0].toInt() and 0xff) shl 16 or ((buffer[1].toInt() and 0xff) shl 8) or (buffer[2].toInt() and 0xff))
    bais.read(buffer, 0, 1)
    type = Type.entries[buffer[0].toInt()]
    bais.read(buffer, 0, 1)
    flags = buffer[0].toInt()
    bais.read(buffer, 0, 4)
    streamId = ((buffer[0].toInt() and 0x7f) shl 24 or ((buffer[1].toInt() and 0xff) shl 16) or ((buffer[2].toInt() and 0xff) shl 8) or (buffer[3].toInt() and 0xff))
    payload = ByteArray(length)
    bais.read(payload)
    splitExtraFromPayload()
  }

  @Throws(Exception::class) fun getOrigPayload(): ByteArray = this.origPayload
  @Throws(Exception::class) fun getExtra(): ByteArray = this.extra

  @Throws(Exception::class)
  open fun toByteArrayWithoutExtra(): ByteArray {
    val bb = ByteBuffer.allocate(origPayload.size + 9)
    bb.put(((origPayload.size ushr 16) and 0xff).toByte())
    bb.put(((origPayload.size ushr 8) and 0xff).toByte())
    bb.put((origPayload.size and 0xff).toByte())
    bb.put((type.ordinal and 0xff).toByte())
    bb.put((flags and FLAG_EXTRA.inv()).toByte())
    bb.putInt(streamId)
    bb.put(origPayload, 0, origPayload.size)
    val array = ByteArray(bb.position())
    bb.flip()
    bb.get(array)
    return array
  }

  @Throws(Exception::class)
  fun toByteArray(): ByteArray {
    val bb = ByteBuffer.allocate(payload.size + 9)
    bb.put(((payload.size ushr 16) and 0xff).toByte())
    bb.put(((payload.size ushr 8) and 0xff).toByte())
    bb.put((payload.size and 0xff).toByte())
    bb.put((type.ordinal and 0xff).toByte())
    bb.put(flags.toByte())
    bb.putInt(streamId)
    bb.put(payload, 0, payload.size)
    val array = ByteArray(bb.position())
    bb.flip()
    bb.get(array)
    return array
  }

  fun removeExtra() {
    if ((flags and FLAG_EXTRA) == 0) return
    val payloadBuf = ByteBuffer.allocate(this.payload.size)
    payloadBuf.put(this.payload)
    payloadBuf.flip()
    val extraLen = payloadBuf.getInt()
    val origPayloadLen = this.payload.size - extraLen - 4
    this.origPayload = ByteArray(origPayloadLen)
    payloadBuf.get(this.origPayload)
    this.payload = this.origPayload
    this.length = this.payload.size
    this.extra = byteArrayOf()
    flags = flags and FLAG_EXTRA.inv()
  }

  @Throws(Exception::class)
  fun saveExtra(extra: ByteArray) {
    val newPayload = ByteBuffer.allocate(this.origPayload.size + extra.size + 4)
    newPayload.putInt(extra.size)
    newPayload.put(this.origPayload)
    newPayload.put(extra)
    val newPayloadArray = ByteArray(newPayload.limit())
    newPayload.flip()
    newPayload.get(newPayloadArray)
    this.payload = newPayloadArray
    this.length = this.payload.size
    this.extra = extra
    this.flags = this.flags or FLAG_EXTRA
  }

  @Throws(Exception::class)
  fun saveOrigPayload(origPayload: ByteArray) {
    if ((flags and FLAG_EXTRA) == 0) {
      this.payload = origPayload
      this.origPayload = origPayload
      this.length = origPayload.size
    } else {
      val newPayload = ByteBuffer.allocate(origPayload.size + this.extra.size + 4)
      newPayload.putInt(this.extra.size)
      newPayload.put(origPayload)
      newPayload.put(this.extra)
      val newPayloadArray = ByteArray(newPayload.limit())
      newPayload.flip()
      newPayload.get(newPayloadArray)
      this.payload = newPayloadArray
      this.origPayload = origPayload
      this.length = this.payload.size
    }
  }

  private fun splitExtraFromPayload() {
    if ((flags and FLAG_EXTRA) == 0) {
      this.origPayload = payload
      this.extra = byteArrayOf()
      return
    }
    val payloadBuf = ByteBuffer.allocate(this.payload.size)
    payloadBuf.put(this.payload)
    payloadBuf.flip()
    val extraLen = payloadBuf.getInt()
    val origPayloadLen = this.payload.size - extraLen - 4
    this.origPayload = ByteArray(origPayloadLen)
    this.extra = ByteArray(extraLen)
    payloadBuf.get(this.origPayload)
    payloadBuf.get(this.extra)
  }

  override fun toString(): String =
    String.format("length=%d, type=%s, flags=0x%x, streamId=%d", length, type.name, flags, streamId)

  companion object {
    @JvmField var TYPE: Type = Type.Unassigned
    @JvmField val FLAG_EXTRA: Int = 0x40
  }
}
