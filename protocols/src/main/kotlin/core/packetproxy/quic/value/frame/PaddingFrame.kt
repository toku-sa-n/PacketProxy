package packetproxy.quic.value.frame

import java.nio.ByteBuffer

data class PaddingFrame(val length: Long) : Frame() {
  override fun getBytes() = ByteArray(length.toInt())

  override fun isAckEliciting() = false

  companion object {
    const val TYPE: Byte = 0x00

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): PaddingFrame {
      var length = 0L
      while (buffer.remaining() > 0) {
        val type = buffer.get()
        if (type != TYPE) {
          buffer.position(buffer.position() - 1)
          break
        }
        length++
      }
      return PaddingFrame(length)
    }
  }
}
