package packetproxy.quic.service.framegenerator.helper

import java.util.TreeSet
import packetproxy.util.err

class ReceivedPacketNumbers {
  private val unreceivedPacketNumbers = TreeSet<Long>()

  fun unreceived(n: Long) {
    unreceivedPacketNumbers.add(n)
  }

  fun received(n: Long) {
    unreceivedPacketNumbers.remove(n)
  }

  fun isReceived(n: Long) = !unreceivedPacketNumbers.contains(n)

  fun isUnreceived(n: Long) = unreceivedPacketNumbers.contains(n)

  fun getSmallestOfRange(largestOfRange: Long, smallestValid: Long): Long {
    assert(smallestValid <= largestOfRange)
    if (unreceivedPacketNumbers.contains(largestOfRange)) {
      err("[QUIC] Error: AckRange: %d isn't in ack_range", largestOfRange)
      return 0
    }
    return getSmallestReceived(largestOfRange, smallestValid)
  }

  fun getSmallestOfGap(largestOfGap: Long, smallestValid: Long): Long {
    assert(smallestValid <= largestOfGap)
    if (!unreceivedPacketNumbers.contains(largestOfGap)) {
      err("[QUIC] Error: AckRange: %d isn't in gap", largestOfGap)
      return 0
    }
    return getSmallestUnreceived(largestOfGap, smallestValid)
  }

  fun clearLessThan(n: Long) {
    unreceivedPacketNumbers.removeIf { it < n }
  }

  private fun getSmallestUnreceived(largestOfGap: Long, smallestValid: Long): Long {
    for (i in largestOfGap downTo smallestValid) if (!unreceivedPacketNumbers.contains(i))
      return i + 1
    return smallestValid
  }

  private fun getSmallestReceived(largestOfRange: Long, smallestValid: Long): Long {
    if (unreceivedPacketNumbers.isEmpty() || largestOfRange < unreceivedPacketNumbers.first())
      return smallestValid
    return maxOf(smallestValid, unreceivedPacketNumbers.floor(largestOfRange)!! + 1)
  }
}
