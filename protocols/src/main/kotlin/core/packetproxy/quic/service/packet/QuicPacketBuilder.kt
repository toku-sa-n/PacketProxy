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
    val builder = requireNotNull(framesBuilder) { "framesBuilder is required" }
    val pair = requireNotNull(connIdPair) { "connIdPair is required" }
    val pn = requireNotNull(packetNumber) { "packetNumber is required" }
    val space = requireNotNull(pnSpaceType) { "pnSpaceType is required" }
    val payload = builder.getBytes()
    return when (space) {
      Constants.PnSpaceType.PnSpaceInitial -> InitialPacket.of(1, pair, pn, payload, token)
      Constants.PnSpaceType.PnSpaceHandshake -> HandshakePacket.of(1, pair, pn, payload)
      Constants.PnSpaceType.PnSpaceApplicationData ->
        ShortHeaderPacket.of(pair.destConnId, pn, payload)
    }
  }

  companion object {
    @JvmStatic fun getBuilder() = QuicPacketBuilder()
  }
}
