package packetproxy.quic.value

import java.nio.ByteBuffer
import java.util.Arrays

data class SimpleBytes(val bytes: ByteArray) {
  fun toByteBuffer() = ByteBuffer.wrap(bytes)

  override fun equals(other: Any?) =
    this === other || (other is SimpleBytes && bytes.contentEquals(other.bytes))

  override fun hashCode() = Arrays.hashCode(bytes)

  companion object {
    @JvmStatic
    fun parse(buffer: ByteBuffer, sizeOfBytes: Long): SimpleBytes {
      val bytes = ByteArray(sizeOfBytes.toInt())
      buffer.get(bytes)
      return SimpleBytes(bytes)
    }

    @JvmStatic
    fun parse(buffer: ByteBuffer, sizeOfBytes: Int): SimpleBytes {
      val bytes = ByteArray(sizeOfBytes)
      buffer.get(bytes)
      return SimpleBytes(bytes)
    }
  }
}
