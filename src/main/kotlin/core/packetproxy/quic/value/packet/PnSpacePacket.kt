package packetproxy.quic.value.packet

import java.util.Optional
import packetproxy.quic.service.frame.Frames
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.frame.AckFrame

interface PnSpacePacket {
  val packetNumber: PacketNumber
  val frames: Frames
  val pnSpaceType: PnSpaceType

  fun isAckEliciting(): Boolean

  fun hasAckFrame(): Boolean

  fun getAckFrame(): Optional<AckFrame>
}
