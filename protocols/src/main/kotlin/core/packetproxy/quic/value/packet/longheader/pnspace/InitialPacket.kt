package packetproxy.quic.value.packet.longheader.pnspace

import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex
import packetproxy.quic.utils.Constants
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.VariableLengthPrecededBytes
import packetproxy.quic.value.key.Key
import packetproxy.quic.value.packet.longheader.LongHeaderPnSpacePacket

class InitialPacket : LongHeaderPnSpacePacket {
  lateinit var token: ByteArray
    private set

  constructor(
    type: Byte,
    version: Int,
    connIdPair: ConnectionIdPair,
    packetNumber: PacketNumber,
    payload: ByteArray,
    token: ByteArray,
  ) : super(type, version, connIdPair, packetNumber, payload) {
    this.token = token
  }

  @Throws(Exception::class)
  constructor(
    buffer: ByteBuffer,
    key: Key,
    largestAckedPn: PacketNumber,
  ) : super(buffer, key, largestAckedPn)

  override fun parseExtra(buffer: ByteBuffer) {
    token = VariableLengthPrecededBytes.parse(buffer).bytes
  }

  override fun getBytesExtra(buffer: ByteBuffer) {
    buffer.put(VariableLengthPrecededBytes.of(token).serialize())
  }

  override val pnSpaceType: PnSpaceType
    get() = Constants.PnSpaceType.PnSpaceInitial

  override fun toString(): String =
    String.format(
      "InitialPacket(token=[%s], super=%s",
      Hex.encodeHexString(token),
      super.toString(),
    )

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is InitialPacket) return false
    if (!super.equals(other)) return false
    return token.contentEquals(other.token)
  }

  override fun hashCode(): Int = 31 * super.hashCode() + token.contentHashCode()

  companion object {
    @JvmField val TYPE: Byte = 0xc0.toByte()

    @JvmStatic fun `is`(type: Byte): Boolean = (type.toInt() and 0xf0) == TYPE.toInt()

    @JvmStatic
    fun of(
      version: Int,
      connIdPair: ConnectionIdPair,
      packetNumber: PacketNumber,
      payload: ByteArray,
      token: ByteArray,
    ): InitialPacket = InitialPacket(TYPE, version, connIdPair, packetNumber, payload, token)
  }
}
