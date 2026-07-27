package packetproxy.quic.value

import java.nio.ByteBuffer

data class VariableLengthInteger(val value: Long) {
  @get:JvmName("getVariableLengthIntegerBytes")
  val bytes: ByteArray
    get() {
      val len = estimateLength(value)
      val buf = ByteBuffer.allocate(len)
      when (len) {
        1 -> buf.put(value.toByte())
        2 -> buf.putShort((value.toShort().toInt() or 0x4000).toShort())
        4 -> buf.putInt(value.toInt() or -0x80000000)
        8 -> buf.putLong(value or -0x4000000000000000L)
      }
      return buf.array()
    }

  companion object {
    @JvmStatic fun of(value: Long) = VariableLengthInteger(value)

    @JvmStatic
    fun parse(bytes: ByteArray): VariableLengthInteger {
      var `val` = 0L
      for (i in bytes.indices) {
        `val` =
          if (i == 0) (bytes[0].toInt() and 0x3f).toLong()
          else (`val` shl 8) or (bytes[i].toLong() and 0xff)
      }
      return VariableLengthInteger(`val`)
    }

    @JvmStatic
    fun parse(buffer: ByteBuffer): VariableLengthInteger {
      val byte0 = buffer.get()
      val length = estimateLength(byte0)
      buffer.position(buffer.position() - 1)
      return parse(SimpleBytes.parse(buffer, length.toLong()).bytes)
    }

    private fun estimateLength(byte0: Byte): Int =
      when (byte0.toInt() and 0xc0) {
        0x00 -> 1
        0x40 -> 2
        0x80 -> 4
        0xc0 -> 8
        else -> -1
      }

    private fun estimateLength(value: Long): Int {
      assert(0 <= value && value < 0x4000000000000000L)
      return when {
        value < 0x40L -> 1
        value < 0x4000L -> 2
        value < 0x40000000L -> 4
        else -> 8
      }
    }
  }
}
