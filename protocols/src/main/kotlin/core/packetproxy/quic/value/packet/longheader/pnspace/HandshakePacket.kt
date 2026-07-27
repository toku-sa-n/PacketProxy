package packetproxy.quic.value.packet.longheader.pnspace

import java.nio.ByteBuffer
import packetproxy.quic.utils.Constants
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.key.Key
import packetproxy.quic.value.packet.longheader.LongHeaderPnSpacePacket

class HandshakePacket : LongHeaderPnSpacePacket {
  constructor(
    type: Byte,
    version: Int,
    connIdPair: ConnectionIdPair,
    packetNumber: PacketNumber,
    payload: ByteArray,
  ) : super(type, version, connIdPair, packetNumber, payload)

  @Throws(Exception::class)
  constructor(
    buffer: ByteBuffer,
    key: Key,
    largestAckedPn: PacketNumber,
  ) : super(buffer, key, largestAckedPn)

  override val pnSpaceType: PnSpaceType
    get() = Constants.PnSpaceType.PnSpaceHandshake

  companion object {
    @JvmField val TYPE: Byte = 0xe0.toByte()

    @JvmStatic fun `is`(type: Byte): Boolean = (type.toInt() and 0xf0) == TYPE.toInt()

    @JvmStatic
    fun of(
      version: Int,
      connIdPair: ConnectionIdPair,
      packetNumber: PacketNumber,
      payload: ByteArray,
    ): HandshakePacket = HandshakePacket(TYPE, version, connIdPair, packetNumber, payload)
  }
}
