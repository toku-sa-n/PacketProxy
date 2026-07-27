package packetproxy.quic.value

import java.time.Instant
import java.util.Optional
import packetproxy.quic.value.frame.AckFrame
import packetproxy.quic.value.packet.PnSpacePacket

data class SentPacket(
  val packetNumber: PacketNumber,
  val timeSent: Instant,
  val packet: PnSpacePacket,
) {
  constructor(packet: PnSpacePacket) : this(packet.packetNumber, Instant.now(), packet)

  fun isAckEliciting() = packet.isAckEliciting()

  fun hasAckFrame() = packet.hasAckFrame()

  val ackFrame: Optional<AckFrame>
    get() = packet.getAckFrame()
}
