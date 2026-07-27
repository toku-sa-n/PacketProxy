package packetproxy.quic.service.pnspace.helper

import java.util.HashMap
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.SentPacket

class LostPackets : Iterable<SentPacket> {
  private val lostPackets = HashMap<PacketNumber, SentPacket>()

  override fun toString() = "Lost ${lostPackets.size} packets"

  fun add(p: SentPacket) {
    lostPackets[p.packetNumber] = p
  }

  fun isEmpty() = lostPackets.isEmpty()

  fun stream() = lostPackets.values.stream()

  override fun iterator() = lostPackets.values.iterator()
}
