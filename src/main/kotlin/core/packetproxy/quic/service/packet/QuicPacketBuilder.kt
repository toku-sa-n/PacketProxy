package packetproxy.quic.service.packet

import packetproxy.quic.service.frame.FramesBuilder
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.packet.QuicPacket
import packetproxy.quic.value.packet.longheader.pnspace.HandshakePacket
import packetproxy.quic.value.packet.longheader.pnspace.InitialPacket
import packetproxy.quic.value.packet.shortheader.ShortHeaderPacket

class QuicPacketBuilder private constructor() {
  var pnSpaceType: Constants.PnSpaceType? = null
  var token = ByteArray(0)
  var framesBuilder: FramesBuilder? = null
  var packetNumber: PacketNumber? = null
  var connIdPair: ConnectionIdPair? = null

  fun setPnSpaceType(t: Constants.PnSpaceType) = apply { pnSpaceType = t }

  fun setToken(t: ByteArray) = apply { token = t }

  fun setFramesBuilder(b: FramesBuilder) = apply { framesBuilder = b }

  fun setConnectionIdPair(p: ConnectionIdPair) = apply { connIdPair = p }

  fun setPacketNumber(n: PacketNumber) = apply { packetNumber = n }

  @Throws(Exception::class)
  fun build(): QuicPacket {
    val payload = framesBuilder!!.getBytes()
    return when (pnSpaceType) {
      Constants.PnSpaceType.PnSpaceInitial ->
        InitialPacket.of(1, connIdPair!!, packetNumber!!, payload, token)
      Constants.PnSpaceType.PnSpaceHandshake ->
        HandshakePacket.of(1, connIdPair!!, packetNumber!!, payload)
      Constants.PnSpaceType.PnSpaceApplicationData ->
        ShortHeaderPacket.of(connIdPair!!.destConnId, packetNumber!!, payload)
      else -> throw Exception("error: unknown packet type")
    }
  }

  companion object {
    @JvmStatic fun getBuilder() = QuicPacketBuilder()
  }
}
