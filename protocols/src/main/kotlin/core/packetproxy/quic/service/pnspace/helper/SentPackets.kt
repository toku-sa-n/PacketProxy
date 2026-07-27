package packetproxy.quic.service.pnspace.helper

import java.util.Comparator
import java.util.HashMap
import java.util.Optional
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.SentPacket
import packetproxy.quic.value.frame.AckFrame
import packetproxy.quic.value.packet.PnSpacePacket

class SentPackets : Iterable<SentPacket> {
  private val sentPacketMap = HashMap<PacketNumber, SentPacket>()

  constructor()

  constructor(list: Collection<SentPacket>) {
    list.forEach { sentPacketMap[it.packetNumber] = it }
  }

  @Synchronized
  fun add(p: SentPacket) {
    sentPacketMap[p.packetNumber] = p
  }

  @Synchronized
  fun sent(packet: PnSpacePacket) {
    sentPacketMap[packet.packetNumber] = SentPacket(packet)
  }

  @Synchronized fun get(pn: PacketNumber) = sentPacketMap[pn]

  @Synchronized fun isEmpty() = sentPacketMap.isEmpty()

  @Synchronized fun hasAnyAckElicitingPacket() = sentPacketMap.values.any { it.isAckEliciting() }

  @Synchronized
  fun getLargest() =
    sentPacketMap.values.maxWithOrNull(Comparator.comparingLong { it.packetNumber.number })?.let {
      Optional.of(it)
    } ?: Optional.empty()

  @Synchronized
  fun getLargestAckFrame() =
    sentPacketMap.values
      .filter { it.hasAckFrame() }
      .mapNotNull { it.ackFrame.orElse(null) }
      .maxWithOrNull(Comparator.comparingLong { it.largestAcknowledged })
      ?.let { Optional.of(it) } ?: Optional.empty()

  @Synchronized
  fun detectAndRemoveAckedPackets(ackFrame: AckFrame): SentPackets {
    val newly = SentPackets()
    ackFrame.ackedPacketNumbers.stream().forEach { pn ->
      sentPacketMap.remove(pn)?.let { newly.add(it) }
    }
    return newly
  }

  fun removePacket(p: SentPacket) = removePacket(p.packetNumber)

  @Synchronized
  fun removePacket(pn: PacketNumber) {
    sentPacketMap.remove(pn)
  }

  @Synchronized fun getUnAckedPackets() = SentPackets(ArrayList(sentPacketMap.values))

  @Synchronized
  fun clear() {
    sentPacketMap.clear()
  }

  override fun iterator() = sentPacketMap.values.iterator()
}
