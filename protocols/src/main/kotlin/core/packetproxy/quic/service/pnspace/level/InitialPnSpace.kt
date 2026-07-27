package packetproxy.quic.service.pnspace.level

import packetproxy.quic.service.connection.Connection
import packetproxy.quic.service.frame.FramesBuilder
import packetproxy.quic.service.packet.QuicPacketBuilder
import packetproxy.quic.service.pnspace.PnSpace
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.packet.QuicPacket
import packetproxy.quic.value.packet.longheader.pnspace.InitialPacket

class InitialPnSpace(conn: Connection) : PnSpace(conn, Constants.PnSpaceType.PnSpaceInitial) {
  override fun receivePacket(quicPacket: QuicPacket) {
    if (quicPacket is InitialPacket) conn.updateDestConnId(quicPacket.getSrcConnId())
    super.receivePacket(quicPacket)
  }

  override fun getAndRemoveSendFramesAndConvertPacketBuilders() =
    sendFrameQueue.pollAll().map {
      QuicPacketBuilder.getBuilder()
        .setPnSpaceType(Constants.PnSpaceType.PnSpaceInitial)
        .setFramesBuilder(FramesBuilder().add(it).addPaddingFramesToEnsure1200Bytes())
    }
}
