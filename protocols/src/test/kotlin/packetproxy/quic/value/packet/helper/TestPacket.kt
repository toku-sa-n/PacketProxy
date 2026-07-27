package packetproxy.quic.value.packet.helper

import java.util.Optional
import packetproxy.quic.service.frame.Frames
import packetproxy.quic.service.frame.FramesBuilder
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.utils.Constants.PnSpaceType.PnSpaceInitial
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.frame.AckFrame
import packetproxy.quic.value.packet.PnSpacePacket
import packetproxy.quic.value.packet.QuicPacket

class TestPacket(type: Byte, override val packetNumber: PacketNumber, override val frames: Frames) :
  QuicPacket(type), PnSpacePacket {

  override fun isAckEliciting(): Boolean = frames.isAckEliciting()

  override fun hasAckFrame(): Boolean = frames.hasAckFrame()

  override fun getAckFrame(): Optional<AckFrame> = frames.getAckFrame()

  override val pnSpaceType: PnSpaceType = PnSpaceInitial

  companion object {
    const val TYPE: Byte = 0x0

    @JvmStatic fun `is`(type: Byte): Boolean = (type.toInt() and 0xf0) == TYPE.toInt()

    @JvmStatic
    fun of(packetNumber: PacketNumber, ackFrame: AckFrame): TestPacket =
      TestPacket(TYPE, packetNumber, FramesBuilder().add(ackFrame).build())

    @JvmStatic
    fun of(packetNumber: PacketNumber): TestPacket = TestPacket(TYPE, packetNumber, Frames.empty)
  }
}
