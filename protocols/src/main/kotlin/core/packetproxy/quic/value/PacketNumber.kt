package packetproxy.quic.value

class PacketNumber private constructor(val number: Long, private val infinite: Boolean) {
  fun isInfinite() = infinite

  fun getTruncatedPacketNumber(largestAckedPn: PacketNumber): TruncatedPacketNumber? =
    if (!infinite) TruncatedPacketNumber(this, largestAckedPn) else null

  fun plus(num: Long) = PacketNumber(number + num, false)

  fun minus(num: Long) = PacketNumber(number - num, false)

  fun minus(packetPn: PacketNumber) = number - packetPn.number

  fun isLargerThan(packetPn: PacketNumber) = number > packetPn.number

  fun isLargerThanOrEquals(packetPn: PacketNumber) = number >= packetPn.number

  fun toBytes() =
    byteArrayOf(
      ((number shr 24) and 0xff).toByte(),
      ((number shr 16) and 0xff).toByte(),
      ((number shr 8) and 0xff).toByte(),
      (number and 0xff).toByte(),
    )

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is PacketNumber) return false
    return number == other.number && infinite == other.infinite
  }

  override fun hashCode(): Int {
    var result = number.hashCode()
    result = 31 * result + infinite.hashCode()
    return result
  }

  override fun toString() = "PacketNumber(${if (infinite) "INF" else number})"

  companion object {
    @JvmField val Infinite = PacketNumber(-1, true)

    @JvmStatic
    fun of(number: Long): PacketNumber {
      assert(number >= 0)
      return PacketNumber(number, false)
    }

    @JvmStatic fun copy(pn: PacketNumber) = PacketNumber(pn.number, pn.infinite)

    @JvmStatic fun max(a: PacketNumber, b: PacketNumber) = if (a.number > b.number) a else b
  }
}
