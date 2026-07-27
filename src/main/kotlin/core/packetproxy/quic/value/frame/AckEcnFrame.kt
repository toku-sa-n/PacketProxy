package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import packetproxy.quic.value.VariableLengthInteger
import packetproxy.quic.value.frame.helper.AckRanges

class AckEcnFrame(
  largestAcknowledged: Long,
  ackDelay: Long,
  ackRangeCount: Long,
  firstAckRange: Long,
  ackRanges: AckRanges,
  val etc0Count: Long,
  val etc1Count: Long,
  val ecnCeCount: Long,
) : AckFrame(largestAcknowledged, ackDelay, ackRangeCount, firstAckRange, ackRanges) {
  override fun isAckEliciting() = false

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is AckEcnFrame || !super.equals(other)) return false
    return etc0Count == other.etc0Count &&
      etc1Count == other.etc1Count &&
      ecnCeCount == other.ecnCeCount
  }

  override fun hashCode(): Int {
    var result = super.hashCode()
    result = 31 * result + etc0Count.hashCode()
    result = 31 * result + etc1Count.hashCode()
    return 31 * result + ecnCeCount.hashCode()
  }

  override fun toString() =
    "AckEcnFrame(largestAcknowledged=$largestAcknowledged, ackDelay=$ackDelay, ackRangeCount=$ackRangeCount, firstAckRange=$firstAckRange, ackRanges=$ackRanges, etc0Count=$etc0Count, etc1Count=$etc1Count, ecnCeCount=$ecnCeCount)"

  companion object {
    const val TYPE: Byte = 0x03

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): AckEcnFrame {
      val ackFrame = AckFrame.parse(buffer)
      return AckEcnFrame(
        ackFrame.largestAcknowledged,
        ackFrame.ackDelay,
        ackFrame.ackRangeCount,
        ackFrame.firstAckRange,
        ackFrame.ackRanges,
        VariableLengthInteger.parse(buffer).value,
        VariableLengthInteger.parse(buffer).value,
        VariableLengthInteger.parse(buffer).value,
      )
    }
  }
}
