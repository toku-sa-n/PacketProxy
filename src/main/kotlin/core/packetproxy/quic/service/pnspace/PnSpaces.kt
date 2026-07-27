package packetproxy.quic.service.pnspace

import com.google.common.collect.ImmutableList
import java.time.Instant
import java.util.Arrays
import java.util.concurrent.LinkedBlockingDeque
import org.apache.commons.lang3.tuple.ImmutablePair
import packetproxy.quic.service.connection.Connection
import packetproxy.quic.service.packet.QuicPacketBuilder
import packetproxy.quic.service.pnspace.level.ApplicationDataPnSpace
import packetproxy.quic.service.pnspace.level.HandshakePnSpace
import packetproxy.quic.service.pnspace.level.InitialPnSpace
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.utils.Constants.PnSpaceType.*
import packetproxy.quic.value.packet.QuicPacket
import packetproxy.quic.value.packet.longheader.pnspace.HandshakePacket
import packetproxy.quic.value.packet.longheader.pnspace.InitialPacket
import packetproxy.quic.value.packet.shortheader.ShortHeaderPacket
import packetproxy.util.Throwing.rethrow

class PnSpaces(private val conn: Connection) {
  private val sendPacketDeque = LinkedBlockingDeque<QuicPacketBuilder>()
  private val pnSpaces = arrayOfNulls<PnSpace>(PnSpaceType.entries.size)

  init {
    pnSpaces[PnSpaceInitial.ordinal] = InitialPnSpace(conn)
    pnSpaces[PnSpaceHandshake.ordinal] = HandshakePnSpace(conn)
    pnSpaces[PnSpaceApplicationData.ordinal] = ApplicationDataPnSpace(conn)
  }

  fun getPnSpace(t: PnSpaceType) = pnSpaces[t.ordinal]!!

  fun receivePacket(packet: QuicPacket) =
    when (packet) {
      is InitialPacket -> pnSpaces[PnSpaceInitial.ordinal]!!.receivePacket(packet)
      is HandshakePacket -> pnSpaces[PnSpaceHandshake.ordinal]!!.receivePacket(packet)
      is ShortHeaderPacket -> pnSpaces[PnSpaceApplicationData.ordinal]!!.receivePacket(packet)
      else -> {}
    }

  fun addSendPackets(packets: List<QuicPacketBuilder>) {
    packets.forEach(rethrow { sendPacketDeque.put(it) })
  }

  fun addSendPacketsFirst(packet: QuicPacketBuilder) {
    sendPacketDeque.addFirst(packet)
  }

  @Throws(Exception::class)
  fun pollSendPackets(): List<QuicPacket> {
    val builder = sendPacketDeque.take()
    val space = conn.getPnSpace(builder.pnSpaceType!!)
    builder.setPacketNumber(space.nextPacketNumberAndIncrement())
    val packet = builder.setConnectionIdPair(conn.connIdPair).build()
    space.addSentPacket(packet)
    return listOf(packet)
  }

  val earliestLossTimeAndSpace: ImmutablePair<Instant, PnSpaceType>
    get() {
      var lossTime = pnSpaces[PnSpaceInitial.ordinal]!!.lossTime
      var space = PnSpaceInitial
      for (t in ImmutableList.of(PnSpaceHandshake, PnSpaceApplicationData)) if (
        lossTime == Instant.MIN || pnSpaces[t.ordinal]!!.lossTime.isBefore(lossTime)
      ) {
        lossTime = pnSpaces[t.ordinal]!!.lossTime
        space = t
      }
      return ImmutablePair.of(lossTime, space)
    }

  val earliestLossTime
    get() = earliestLossTimeAndSpace.left

  fun hasAnyAckElicitingPacket() =
    Arrays.stream(pnSpaces).anyMatch { it!!.hasAnyAckElicitingPacket() }
}
