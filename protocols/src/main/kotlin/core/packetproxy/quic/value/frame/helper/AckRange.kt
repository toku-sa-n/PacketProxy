package packetproxy.quic.value.frame.helper

import java.nio.ByteBuffer
import packetproxy.quic.utils.PacketNumbers
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.VariableLengthInteger

data class AckRange(val gap: Long, val ackRangeLength: Long) {
  constructor(
    buffer: ByteBuffer
  ) : this(VariableLengthInteger.parse(buffer).value, VariableLengthInteger.parse(buffer).value)

  fun size() = gap + ackRangeLength + 2

  fun getAckPacketNumbers(largestGapPn: Long): PacketNumbers {
    val largestAckPn = largestGapPn - gap - 1
    val pns = PacketNumbers()
    var pn = largestAckPn
    while (pn >= largestAckPn - ackRangeLength) {
      pns.add(PacketNumber.of(pn))
      pn--
    }
    return pns
  }

  fun serialize(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(VariableLengthInteger.of(gap).bytes)
    buffer.put(VariableLengthInteger.of(ackRangeLength).bytes)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun toString() = "gap:$gap, ackRangeLength:$ackRangeLength"
}
