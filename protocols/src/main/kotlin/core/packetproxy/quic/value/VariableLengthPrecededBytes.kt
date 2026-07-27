package packetproxy.quic.value

import java.nio.ByteBuffer

class VariableLengthPrecededBytes private constructor(val bytes: ByteArray) {
  fun serialize() = (VariableLengthInteger.of(bytes.size.toLong()).bytes + bytes)

  companion object {
    @JvmStatic fun of(bytes: ByteArray) = VariableLengthPrecededBytes(bytes)

    @JvmStatic
    fun parse(buffer: ByteBuffer): VariableLengthPrecededBytes {
      val length = VariableLengthInteger.parse(buffer).value
      var bytes = ByteArray(0)
      if (length > 0) {
        bytes = ByteArray(length.toInt())
        buffer.get(bytes)
      }
      return VariableLengthPrecededBytes(bytes)
    }
  }
}
