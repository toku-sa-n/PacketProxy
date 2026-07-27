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

package packetproxy.quic.value.packet.longheader

import java.nio.ByteBuffer
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.quic.value.FixedLengthPrecededBytes
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.packet.QuicPacket

open class LongHeaderPacket
protected constructor(type: Byte, version: Int, connectionIdPair: ConnectionIdPair) :
  QuicPacket(type) {
  val version: Int = version
  val connectionIdPair: ConnectionIdPair = connectionIdPair

  protected constructor(
    buffer: ByteBuffer
  ) : this(buffer.get(), buffer.int, parseConnectionIdPair(buffer))

  override fun size(): Int = getBytes().size

  override fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(type)
    buffer.putInt(version)
    buffer.put(FixedLengthPrecededBytes.of(connectionIdPair.destConnId.bytes).serialize())
    buffer.put(FixedLengthPrecededBytes.of(connectionIdPair.srcConnId.bytes).serialize())
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun getBytes(newlyPnLength: Int): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(getType(newlyPnLength))
    buffer.putInt(version)
    buffer.put(FixedLengthPrecededBytes.of(connectionIdPair.destConnId.bytes).serialize())
    buffer.put(FixedLengthPrecededBytes.of(connectionIdPair.srcConnId.bytes).serialize())
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  protected fun getMaskedBytes(newlyPnLength: Int, maskKey: ByteArray): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(getMaskedBytes(newlyPnLength, PacketHeaderType.LongHeaderType, maskKey))
    buffer.putInt(version)
    buffer.put(FixedLengthPrecededBytes.of(connectionIdPair.destConnId.bytes).serialize())
    buffer.put(FixedLengthPrecededBytes.of(connectionIdPair.srcConnId.bytes).serialize())
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  fun getSrcConnId(): ConnectionId = connectionIdPair.srcConnId

  fun getDestConnId(): ConnectionId = connectionIdPair.destConnId

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is LongHeaderPacket) return false
    return type == other.type &&
      version == other.version &&
      connectionIdPair == other.connectionIdPair
  }

  override fun hashCode(): Int {
    var result = type.hashCode()
    result = 31 * result + version
    result = 31 * result + connectionIdPair.hashCode()
    return result
  }

  companion object {
    private fun parseConnectionIdPair(buffer: ByteBuffer): ConnectionIdPair {
      val destConnId = ConnectionId.of(FixedLengthPrecededBytes.parse(buffer).bytes)
      val srcConnId = ConnectionId.of(FixedLengthPrecededBytes.parse(buffer).bytes)
      return ConnectionIdPair.of(srcConnId, destConnId)
    }

    @JvmStatic fun `is`(type: Byte): Boolean = (type.toInt() and 0xc0) == 0xc0

    @JvmStatic
    fun getDestConnId(buffer: ByteBuffer): ConnectionId {
      val savedPosition = buffer.position()
      buffer.get()
      buffer.int
      val destConnId = FixedLengthPrecededBytes.parse(buffer).bytes
      buffer.position(savedPosition)
      return ConnectionId.of(destConnId)
    }
  }
}
