package packetproxy.quic.service.framegenerator

import packetproxy.quic.service.framegenerator.helper.ReceivedPacketNumbers
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.frame.AckFrame
import packetproxy.quic.value.frame.helper.AckRange
import packetproxy.quic.value.frame.helper.AckRanges
import packetproxy.util.err

class AckFrameGenerator {
  private var largestAckedPn = -1L
  private var smallestValidPn = 0L
  private val receivedPacketNumbers = ReceivedPacketNumbers()

  fun received(packetNumber: PacketNumber) = received(packetNumber.number)

  fun received(receivedPn: Long) {
    if (receivedPn < smallestValidPn) return
    if (largestAckedPn < receivedPn) {
      for (i in largestAckedPn + 1 until receivedPn) receivedPacketNumbers.unreceived(i)
      receivedPacketNumbers.received(receivedPn)
      largestAckedPn = receivedPn
    } else if (receivedPn < largestAckedPn) receivedPacketNumbers.received(receivedPn)
  }

  fun confirmedAckFrame(f: AckFrame) {
    smallestValidPn = f.largestAcknowledged + 1
    receivedPacketNumbers.clearLessThan(smallestValidPn)
    if (largestAckedPn == f.largestAcknowledged) largestAckedPn = -1
  }

  private fun ackRangeExists(n: Long) = n >= smallestValidPn + 2

  fun generateAckFrame(): AckFrame? {
    if (largestAckedPn == -1L) return null
    val smallestOfRange = receivedPacketNumbers.getSmallestOfRange(largestAckedPn, smallestValidPn)
    val firstAckRange = largestAckedPn - smallestOfRange
    if (!ackRangeExists(smallestOfRange))
      return AckFrame(largestAckedPn, 0, 0, firstAckRange, AckRanges.emptyAckRanges)
    val ackRanges = generateAckRanges(smallestOfRange)
    return AckFrame(largestAckedPn, 0, ackRanges.size().toLong(), firstAckRange, ackRanges)
  }

  fun getLargestAckedPn() =
    if (largestAckedPn == -1L) PacketNumber.Infinite else PacketNumber.of(largestAckedPn)

  fun getSmallestValidPn() = PacketNumber.of(smallestValidPn - 1)

  fun generateAckRanges(smallestOfRange: Long): AckRanges {
    val list = mutableListOf<AckRange>()
    var cur = smallestOfRange
    while (ackRangeExists(cur)) {
      val r = generateAckRange(cur - 1) ?: break
      list.add(r)
      cur -= r.size()
    }
    return AckRanges(list)
  }

  fun generateAckRange(largestOfGap: Long): AckRange? {
    if (receivedPacketNumbers.isReceived(largestOfGap)) {
      err("largestGap(%d) is not a gap", largestOfGap)
      return null
    }
    val smallestOfGap = receivedPacketNumbers.getSmallestOfGap(largestOfGap, smallestValidPn)
    if (smallestOfGap == smallestValidPn) return null
    val largestOfRange = smallestOfGap - 1
    val smallestOfRange = receivedPacketNumbers.getSmallestOfRange(largestOfRange, smallestValidPn)
    return AckRange(largestOfGap - smallestOfGap, largestOfRange - smallestOfRange)
  }
}
