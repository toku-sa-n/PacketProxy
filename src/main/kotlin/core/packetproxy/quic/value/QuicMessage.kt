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

class QuicMessage private constructor(val streamId: StreamId, val data: ByteArray) {

  fun streamIdIs(streamId: StreamId): Boolean = streamId == this.streamId

  fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(data.size + 16)
    buffer.put(this.streamId.getBytes())
    buffer.putLong(data.size.toLong())
    buffer.put(data)
    return buffer.array()
  }

  override fun toString(): String =
    String.format("QuicMessage(streamId=%s, dataLen=%d)", streamId, data.size)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is QuicMessage) return false
    return streamId == other.streamId && data.contentEquals(other.data)
  }

  override fun hashCode(): Int = 31 * streamId.hashCode() + data.contentHashCode()

  companion object {
    @JvmStatic
    fun of(streamId: StreamId, data: ByteArray): QuicMessage = QuicMessage(streamId, data)
  }
}
