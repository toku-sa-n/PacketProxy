package packetproxy.quic.value.packet.shortheader

import java.nio.ByteBuffer
import java.util.Optional
import org.apache.commons.lang3.ArrayUtils
import packetproxy.quic.service.frame.Frames
import packetproxy.quic.utils.Constants
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.TruncatedPacketNumber
import packetproxy.quic.value.frame.AckFrame
import packetproxy.quic.value.key.Key
import packetproxy.quic.value.packet.PnSpacePacket
import packetproxy.quic.value.packet.QuicPacket
import packetproxy.util.errWithStackTrace

class ShortHeaderPacket : QuicPacket, PnSpacePacket {
  val destConnId: ConnectionId
  private val packetNumberValue: PacketNumber
  val payload: ByteArray

  constructor(
    type: Byte,
    destConnId: ConnectionId,
    packetNumber: PacketNumber,
    payload: ByteArray,
  ) : super(type) {
    this.destConnId = destConnId
    packetNumberValue = packetNumber
    this.payload = payload
  }

  @Throws(Exception::class)
  constructor(buffer: ByteBuffer, key: Key, largestAckedPn: PacketNumber) : super(buffer) {
    val startPosition = buffer.position() - super.size()

    destConnId = ConnectionId.parse(buffer, Constants.CONNECTION_ID_SIZE.toLong())

    val packetNumberPosition = buffer.position()
    buffer.position(buffer.position() + 4)
    val sample = SimpleBytes.parse(buffer, 16).bytes

    val maskKey = key.getMaskForHeaderProtection(sample)

    unmaskType(PacketHeaderType.ShortHeaderType, maskKey)
    val packetNumberLength = origPnLength

    buffer.position(packetNumberPosition)
    val maskedTruncatedPn = SimpleBytes.parse(buffer, packetNumberLength.toLong()).bytes
    val truncatedPn = TruncatedPacketNumber.unmaskTruncatedPacketNumber(maskedTruncatedPn, maskKey)

    val payloadPosition = buffer.position()
    val payloadLength = buffer.limit() - payloadPosition
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

    val type = getType(truncatedPn.size)
    headerBuffer.put(type)
    headerBuffer.put(destConnId.bytes)
    headerBuffer.put(truncatedPn)
    headerBuffer.flip()
    val header = SimpleBytes.parse(headerBuffer, headerBuffer.remaining().toLong()).bytes

    val encryptedPayload = key.encryptPayload(truncatedPn, payload, header)
    val sample = ArrayUtils.subarray((truncatedPn + encryptedPayload), 4, 20)
    val maskKey = key.getMaskForHeaderProtection(sample)
    val maskedType = getMaskedType(truncatedPn.size, PacketHeaderType.ShortHeaderType, maskKey)
    val maskedTruncatedPn = TruncatedPacketNumber.maskTruncatedPacketNumber(truncatedPn, maskKey)

    val buffer = ByteBuffer.allocate(1500)
    buffer.put(maskedType)
    buffer.put(destConnId.bytes)
    buffer.put(maskedTruncatedPn)
    buffer.put(encryptedPayload)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun size(): Int = getBytes().size

  override fun toString(): String =
    try {
      String.format(
        "ShortHeaderPacket(connIdPair=%s, packetNumber=%s, payload=%s)",
        destConnId,
        packetNumberValue,
        Frames.parse(payload),
      )
    } catch (e: Exception) {
      errWithStackTrace(e)
      ""
    }

  override val packetNumber: PacketNumber
    get() = packetNumberValue

  override fun isAckEliciting(): Boolean = Frames.parse(payload).isAckEliciting()

  override fun hasAckFrame(): Boolean = Frames.parse(payload).hasAckFrame()

  override fun getAckFrame(): Optional<AckFrame> = Frames.parse(payload).getAckFrame()

  override val pnSpaceType: PnSpaceType
    get() = Constants.PnSpaceType.PnSpaceApplicationData

  override val frames: Frames
    get() = Frames.parse(payload)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is ShortHeaderPacket) return false
    return type == other.type &&
      destConnId == other.destConnId &&
      packetNumberValue == other.packetNumberValue &&
      payload.contentEquals(other.payload)
  }

  override fun hashCode(): Int {
    var result = type.hashCode()
    result = 31 * result + destConnId.hashCode()
    result = 31 * result + packetNumberValue.hashCode()
    result = 31 * result + payload.contentHashCode()
    return result
  }

  companion object {
    @JvmField val TYPE: Byte = 0x40

    @JvmStatic fun `is`(type: Byte): Boolean = (type.toInt() and 0xc0) == TYPE.toInt()

    @JvmStatic
    fun getDestConnId(buffer: ByteBuffer): ConnectionId {
      val savedPosition = buffer.position()
      buffer.get()
      val destConnId = SimpleBytes.parse(buffer, Constants.CONNECTION_ID_SIZE.toLong()).bytes
      buffer.position(savedPosition)
      return ConnectionId.of(destConnId)
    }

    @JvmStatic
    fun of(
      destConnId: ConnectionId,
      packetNumber: PacketNumber,
      payload: ByteArray,
    ): ShortHeaderPacket = ShortHeaderPacket(TYPE, destConnId, packetNumber, payload)
  }
}
