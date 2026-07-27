package packetproxy.quic.value.frame.helper

import java.nio.ByteBuffer
import packetproxy.quic.utils.PacketNumbers
import packetproxy.quic.value.SimpleBytes

class AckRanges : Iterable<AckRange> {
  val ackRanges: List<AckRange>

  constructor(buffer: ByteBuffer, rangeCount: Long) {
    val list = mutableListOf<AckRange>()
    for (i in 0 until rangeCount) list.add(AckRange(buffer))
    ackRanges = list
  }

  constructor(ackRanges: List<AckRange>) {
    this.ackRanges = ackRanges
  }

  private constructor() {
    ackRanges = emptyList()
  }

  fun getAckPacketNumbers(largestGapPnIn: Long): PacketNumbers {
    var largestGapPn = largestGapPnIn
    val pns = PacketNumbers()
    for (ackRange in ackRanges) {
      pns.addAll(ackRange.getAckPacketNumbers(largestGapPn))
      largestGapPn -= ackRange.size()
    }
    return pns
  }

  fun serialize(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    for (ackRange in ackRanges) buffer.put(ackRange.serialize())
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun toString(): String {
    var rangeMsg = ""
    for (ackRange in ackRanges) rangeMsg += "$ackRange|"
    return "{$rangeMsg}"
  }

  fun size() = ackRanges.size

  operator fun get(index: Int) = ackRanges[0]

  override fun iterator() = ackRanges.iterator()

  override fun equals(other: Any?) =
    this === other || (other is AckRanges && ackRanges == other.ackRanges)

  override fun hashCode() = ackRanges.hashCode()

  companion object {
    @JvmField val emptyAckRanges = AckRanges()
  }
}
