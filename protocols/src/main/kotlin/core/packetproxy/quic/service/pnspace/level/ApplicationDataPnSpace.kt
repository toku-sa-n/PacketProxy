package packetproxy.quic.service.pnspace.level

import packetproxy.quic.service.connection.Connection
import packetproxy.quic.service.frame.FramesBuilder
import packetproxy.quic.service.framegenerator.MessagesToStreamFrames
import packetproxy.quic.service.packet.QuicPacketBuilder
import packetproxy.quic.service.pnspace.PnSpace
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.QuicMessage

class ApplicationDataPnSpace(conn: Connection) :
  PnSpace(conn, Constants.PnSpaceType.PnSpaceApplicationData) {
  val msgToStreamFrames = MessagesToStreamFrames()

  override fun addSendQuicMessage(msg: QuicMessage) {
    msgToStreamFrames.put(msg)
    super.addSendFrames(msgToStreamFrames.get())
  }

  override fun getAndRemoveSendFramesAndConvertPacketBuilders() =
    sendFrameQueue.pollAll().map {
      QuicPacketBuilder.getBuilder()
        .setPnSpaceType(Constants.PnSpaceType.PnSpaceApplicationData)
        .setFramesBuilder(FramesBuilder().add(it))
    }
}
