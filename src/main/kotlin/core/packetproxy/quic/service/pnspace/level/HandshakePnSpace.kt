package packetproxy.quic.service.pnspace.level

import packetproxy.quic.service.connection.Connection
import packetproxy.quic.service.frame.FramesBuilder
import packetproxy.quic.service.packet.QuicPacketBuilder
import packetproxy.quic.service.pnspace.PnSpace
import packetproxy.quic.utils.Constants

class HandshakePnSpace(conn: Connection) : PnSpace(conn, Constants.PnSpaceType.PnSpaceHandshake) {
  override fun getAndRemoveSendFramesAndConvertPacketBuilders() =
    sendFrameQueue.pollAll().map {
      QuicPacketBuilder.getBuilder()
        .setPnSpaceType(Constants.PnSpaceType.PnSpaceHandshake)
        .setFramesBuilder(FramesBuilder().add(it))
    }
}
