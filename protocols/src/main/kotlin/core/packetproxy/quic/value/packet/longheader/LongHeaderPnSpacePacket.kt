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
import java.util.Optional
import org.apache.commons.lang3.ArrayUtils
import packetproxy.quic.service.frame.Frames
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.TruncatedPacketNumber
import packetproxy.quic.value.VariableLengthInteger
import packetproxy.quic.value.frame.AckFrame
import packetproxy.quic.value.key.Key
import packetproxy.quic.value.packet.PnSpacePacket

open class LongHeaderPnSpacePacket : LongHeaderPacket, PnSpacePacket {
  private val packetNumberValue: PacketNumber
  val payload: ByteArray

  protected constructor(
    type: Byte,
    version: Int,
    connIdPair: ConnectionIdPair,
    packetNumber: PacketNumber,
    payload: ByteArray,
  ) : super(type, version, connIdPair) {
    packetNumberValue = packetNumber
    this.payload = payload
  }

  @Throws(Exception::class)
  protected constructor(
    buffer: ByteBuffer,
    key: Key,
    largestAckedPn: PacketNumber,
  ) : super(buffer) {
    val startPosition = buffer.position() - super.size()
    parseExtra(buffer)

    val length = VariableLengthInteger.parse(buffer).value

    val packetNumberPosition = buffer.position()
    buffer.position(buffer.position() + 4)
    val sample = SimpleBytes.parse(buffer, 16).bytes

    val maskKey = key.getMaskForHeaderProtection(sample)

    unmaskType(PacketHeaderType.LongHeaderType, maskKey)
    val packetNumberLength = origPnLength

    buffer.position(packetNumberPosition)
    val maskedTruncatedPn = SimpleBytes.parse(buffer, packetNumberLength.toLong()).bytes
    val truncatedPn = TruncatedPacketNumber.unmaskTruncatedPacketNumber(maskedTruncatedPn, maskKey)

    val payloadPosition = buffer.position()
    val payloadLength = length.toInt() - packetNumberLength
    val encodedPayload = SimpleBytes.parse(buffer, payloadLength.toLong()).bytes
    val positionPacketEnd = buffer.position()

    buffer.position(startPosition)
    val header = SimpleBytes.parse(buffer, (payloadPosition - startPosition).toLong()).bytes
    header[0] = type
    for (i in truncatedPn.indices) {
      header[packetNumberPosition - startPosition + i] = truncatedPn[i]
    }

    packetNumberValue = TruncatedPacketNumber(truncatedPn).getPacketNumber(largestAckedPn)
    payload = key.decryptPayload(packetNumberValue.toBytes(), encodedPayload, header)

    buffer.position(positionPacketEnd)
  }

  @Throws(Exception::class)
  fun getBytes(key: Key, largestAckedPn: PacketNumber): ByteArray {
    val headerBuffer = ByteBuffer.allocate(1500)

    var truncatedPn = packetNumberValue.getTruncatedPacketNumber(largestAckedPn)!!.bytes
    if (truncatedPn.size + payload.size + 16 < 20) {
      val dummyBytesLength = 20 - truncatedPn.size - payload.size - 16
      truncatedPn = (ByteArray(dummyBytesLength) + truncatedPn)
    }

    val payloadLength =
      VariableLengthInteger.of((truncatedPn.size + payload.size + 16).toLong()).bytes

    headerBuffer.put(super.getBytes(truncatedPn.size))
    getBytesExtra(headerBuffer)
    headerBuffer.put(payloadLength)
    headerBuffer.put(truncatedPn)
    headerBuffer.flip()
    val header = SimpleBytes.parse(headerBuffer, headerBuffer.remaining().toLong()).bytes

    val encryptedPayload = key.encryptPayload(truncatedPn, payload, header)
    val sample = ArrayUtils.subarray((truncatedPn + encryptedPayload), 4, 20)
    val maskKey = key.getMaskForHeaderProtection(sample)
    val maskedTruncatedPn = TruncatedPacketNumber.maskTruncatedPacketNumber(truncatedPn, maskKey)

    val buffer = ByteBuffer.allocate(1500)
    buffer.put(super.getMaskedBytes(truncatedPn.size, maskKey))
    getBytesExtra(buffer)
    buffer.put(payloadLength)
    buffer.put(maskedTruncatedPn)
    buffer.put(encryptedPayload)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override val frames: Frames
    get() = Frames.parse(payload)

  override val packetNumber: PacketNumber
    get() = packetNumberValue

  override fun isAckEliciting(): Boolean = Frames.parse(payload).isAckEliciting()

  override fun hasAckFrame(): Boolean = Frames.parse(payload).hasAckFrame()

  override fun getAckFrame(): Optional<AckFrame> = Frames.parse(payload).getAckFrame()

  override val pnSpaceType: PnSpaceType
    get() = PnSpaceType.PnSpaceInitial

  override fun toString(): String =
    String.format(
      "LongHeaderPacket(version=%d, connIdPair=%s, packetNumber=%s, payload=%s",
      version,
      connectionIdPair,
      packetNumberValue,
      Frames.parse(payload),
    )

  protected open fun parseExtra(buffer: ByteBuffer) {}

  @Throws(Exception::class) protected open fun getBytesExtra(buffer: ByteBuffer) {}

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is LongHeaderPnSpacePacket) return false
    if (!super.equals(other)) return false
    return packetNumberValue == other.packetNumberValue && payload.contentEquals(other.payload)
  }

  override fun hashCode(): Int {
    var result = super.hashCode()
    result = 31 * result + packetNumberValue.hashCode()
    result = 31 * result + payload.contentHashCode()
    return result
  }
}
