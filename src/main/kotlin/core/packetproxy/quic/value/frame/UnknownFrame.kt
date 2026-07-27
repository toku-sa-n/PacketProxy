package packetproxy.quic.value.frame

import java.nio.ByteBuffer

data class UnknownFrame(val type: Byte) : Frame() {
  override fun getBytes() = byteArrayOf(type)

  override fun isAckEliciting() = false

  override fun toString() = "Unknown(type=%02x)".format(type)

  companion object {
    @JvmStatic fun supportedTypes(): List<Byte> = listOf()

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic fun parse(buffer: ByteBuffer) = UnknownFrame(buffer.get())
  }
}
