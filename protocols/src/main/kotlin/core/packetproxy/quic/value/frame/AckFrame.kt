package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import packetproxy.quic.utils.PacketNumbers
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.VariableLengthInteger
import packetproxy.quic.value.frame.helper.AckRanges

open class AckFrame(
  open val largestAcknowledged: Long,
  open val ackDelay: Long,
  open val ackRangeCount: Long,
  open val firstAckRange: Long,
  open val ackRanges: AckRanges,
) : Frame() {
  val largestAckedPn: PacketNumber
    get() = PacketNumber.of(largestAcknowledged)

  val ackedPacketNumbers: PacketNumbers
    get() = computeAckedPacketNumbers()

  private fun computeAckedPacketNumbers(): PacketNumbers {
    val pns = PacketNumbers()
    var pn = largestAcknowledged
    while (pn >= largestAcknowledged - firstAckRange) {
      pns.add(PacketNumber.of(pn))
      pn--
    }
    pns.addAll(ackRanges.getAckPacketNumbers(largestAcknowledged - firstAckRange - 1))
    return pns
  }

  override fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(TYPE)
    buffer.put(VariableLengthInteger.of(largestAcknowledged).bytes)
    buffer.put(VariableLengthInteger.of(ackDelay).bytes)
    buffer.put(VariableLengthInteger.of(ackRanges.size().toLong()).bytes)
    buffer.put(VariableLengthInteger.of(firstAckRange).bytes)
    buffer.put(ackRanges.serialize())
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun isAckEliciting() = false

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is AckFrame) return false
    return largestAcknowledged == other.largestAcknowledged &&
      ackDelay == other.ackDelay &&
      ackRangeCount == other.ackRangeCount &&
      firstAckRange == other.firstAckRange &&
      ackRanges == other.ackRanges
  }

  override fun hashCode(): Int {
    var result = largestAcknowledged.hashCode()
    result = 31 * result + ackDelay.hashCode()
    result = 31 * result + ackRangeCount.hashCode()
    result = 31 * result + firstAckRange.hashCode()
    return 31 * result + ackRanges.hashCode()
  }

  override fun toString() =
    "AckFrame(largestAcknowledged=$largestAcknowledged, ackDelay=$ackDelay, ackRangeCount=$ackRangeCount, firstAckRange=$firstAckRange, ackRanges=$ackRanges)"

  companion object {
    const val TYPE: Byte = 0x02

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): AckFrame {
      buffer.get()
      val largestAcknowledged = VariableLengthInteger.parse(buffer).value
      val ackDelay = VariableLengthInteger.parse(buffer).value
      val ackRangeCount = VariableLengthInteger.parse(buffer).value
      val firstAckRange = VariableLengthInteger.parse(buffer).value
      return AckFrame(
        largestAcknowledged,
        ackDelay,
        ackRangeCount,
        firstAckRange,
        AckRanges(buffer, ackRangeCount),
      )
    }
  }
}
