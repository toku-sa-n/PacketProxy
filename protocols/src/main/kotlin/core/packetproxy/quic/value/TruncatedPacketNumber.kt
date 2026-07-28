package packetproxy.quic.value

import java.nio.ByteBuffer
import java.util.Arrays
import org.apache.commons.codec.binary.Hex
import packetproxy.util.err

data class TruncatedPacketNumber(private val truncatedPacketNumber: ByteArray) {
  constructor(
    packetNumber: PacketNumber,
    largestAckPn: PacketNumber,
  ) : this(encode(packetNumber, largestAckPn))

  @get:JvmName("getTruncatedPacketNumberBytes")
  val bytes
    get() = truncatedPacketNumber

  fun getPacketNumber(largestAckedPn: PacketNumber) =
    PacketNumber.of(decode(truncatedPacketNumber, largestAckedPn))

  override fun toString() = "TruncatedPacketNumber([${Hex.encodeHexString(truncatedPacketNumber)}])"

  override fun equals(other: Any?) =
    this === other ||
      (other is TruncatedPacketNumber &&
        truncatedPacketNumber.contentEquals(other.truncatedPacketNumber))

  override fun hashCode() = Arrays.hashCode(truncatedPacketNumber)

  companion object {
    @JvmStatic
    fun unmaskTruncatedPacketNumber(truncatedPacketNumber: ByteArray, maskKey: ByteArray) =
      maskTruncatedPacketNumber(truncatedPacketNumber, maskKey)

    @JvmStatic
    fun maskTruncatedPacketNumber(truncatedPacketNumber: ByteArray, maskKey: ByteArray): ByteArray {
      val pn = ByteBuffer.allocate(truncatedPacketNumber.size)
      for (i in truncatedPacketNumber.indices) pn.put(
        (truncatedPacketNumber[i].toInt() xor maskKey[1 + i].toInt()).toByte()
      )
      pn.flip()
      return pn.array()
    }

    private fun encode(packetNumber: PacketNumber, largestAckPn: PacketNumber): ByteArray {
      val numUnAcked =
        if (largestAckPn.isInfinite()) packetNumber.number + 1
        else packetNumber.number - largestAckPn.number
      val minBits = Math.log(numUnAcked.toDouble()) / Math.log(2.0) + 1
      val numBytes = Math.ceil(minBits / 8.0).toInt()
      return truncate(packetNumber.number, numBytes)!!
    }

    private fun decode(truncatedPacketNumberBytes: ByteArray, largestAckPn: PacketNumber): Long {
      val truncatedPn = bytesToLong(truncatedPacketNumberBytes)
      val bits = truncatedPacketNumberBytes.size * 8
      val expectedPn = largestAckPn.number + 1
      val pnWindow = 1L shl bits
      val pnHalfWindow = pnWindow / 2
      val pnMask = (pnWindow - 1).inv()
      val candidatePn = (expectedPn and pnMask) or truncatedPn
      if (candidatePn <= expectedPn - pnHalfWindow && candidatePn < (1L shl 62) - pnWindow)
        return candidatePn + pnWindow
      if (candidatePn > expectedPn + pnHalfWindow && candidatePn >= pnWindow)
        return candidatePn - pnWindow
      return candidatePn
    }

    private fun bytesToLong(bytes: ByteArray): Long =
      when (bytes.size) {
        1 -> (bytes[0].toInt() and 0xff).toLong()
        2 -> (((bytes[0].toInt() and 0xff) shl 8) or (bytes[1].toInt() and 0xff)).toLong()
        3 ->
          (((bytes[0].toInt() and 0xff) shl 16) or
              ((bytes[1].toInt() and 0xff) shl 8) or
              (bytes[2].toInt() and 0xff))
            .toLong()
        4 ->
          ((bytes[0].toLong() and 0xff) shl 24) or
            ((bytes[1].toLong() and 0xff) shl 16) or
            ((bytes[2].toLong() and 0xff) shl 8) or
            (bytes[3].toLong() and 0xff)
        else -> {
          err("[Error] can't decode packetNumber from ByteArray to Long")
          0
        }
      }

    private fun truncate(packetNumber: Long, byteLength: Int): ByteArray? =
      when {
        byteLength == 0 || byteLength == 1 -> byteArrayOf((packetNumber and 0xff).toByte())
        byteLength == 2 ->
          byteArrayOf(((packetNumber shr 8) and 0xff).toByte(), (packetNumber and 0xff).toByte())
        byteLength == 3 ->
          byteArrayOf(
            ((packetNumber shr 16) and 0xff).toByte(),
            ((packetNumber shr 8) and 0xff).toByte(),
            (packetNumber and 0xff).toByte(),
          )
        byteLength >= 4 ->
          byteArrayOf(
            ((packetNumber shr 24) and 0xff).toByte(),
            ((packetNumber shr 16) and 0xff).toByte(),
            ((packetNumber shr 8) and 0xff).toByte(),
            (packetNumber and 0xff).toByte(),
          )
        else -> {
          err(
            "[Error] can't encode packetNumber from Long to ByteArray (byteLength=%d)",
            byteLength,
          )
          null
        }
      }
  }
}
