package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import java.util.Arrays

data class PingFrame(val length: Long) : Frame() {
  override fun getBytes(): ByteArray {
    val bytes = ByteArray(length.toInt())
    Arrays.fill(bytes, TYPE)
    return bytes
  }

  override fun isAckEliciting() = true

  companion object {
    const val TYPE: Byte = 0x01

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): PingFrame {
      var length = 0L
      while (buffer.remaining() > 0) {
        val type = buffer.get()
        if (type != TYPE) {
          buffer.position(buffer.position() - 1)
          break
        }
        length++
      }
      return PingFrame(length)
    }

    @JvmStatic fun generate() = PingFrame(1)
  }
}
