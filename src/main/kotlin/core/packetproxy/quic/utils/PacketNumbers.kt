package packetproxy.quic.utils

import java.util.stream.Collectors
import java.util.stream.Stream
import packetproxy.quic.value.PacketNumber

class PacketNumbers {
  private val packetNumberList = mutableListOf<PacketNumber>()

  fun add(packetNumber: PacketNumber) = packetNumberList.add(packetNumber)

  fun addAll(packetNumbers: PacketNumbers) = packetNumberList.addAll(packetNumbers.packetNumberList)

  fun stream(): Stream<PacketNumber> = packetNumberList.stream()

  fun isEmpty() = packetNumberList.isEmpty()

  fun largest(): PacketNumber? =
    packetNumberList.stream().max(Comparator.comparingLong { it.number }).orElse(null)

  override fun toString() =
    "PacketNumbers([${packetNumberList.stream().map { it.number.toString() }.collect(Collectors.joining(","))}])"
}
