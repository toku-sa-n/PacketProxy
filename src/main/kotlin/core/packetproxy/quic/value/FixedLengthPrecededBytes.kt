package packetproxy.quic.value

import java.nio.ByteBuffer

class FixedLengthPrecededBytes private constructor(val bytes: ByteArray) {
  fun serialize(): ByteArray {
    val buffer = ByteBuffer.allocate(255)
    buffer.put(bytes.size.toByte())
    buffer.put(bytes)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  companion object {
    @JvmStatic fun of(bytes: ByteArray) = FixedLengthPrecededBytes(bytes)

    @JvmStatic
    fun parse(buffer: ByteBuffer): FixedLengthPrecededBytes {
      val length = buffer.get()
      val bytes = ByteArray(length.toInt())
      buffer.get(bytes)
      return FixedLengthPrecededBytes(bytes)
    }
  }
}
