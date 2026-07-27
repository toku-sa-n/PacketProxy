package packetproxy.quic.value.frame

import java.nio.ByteBuffer

class HandshakeDoneFrame : Frame() {
  override fun getBytes() = byteArrayOf(TYPE)

  override fun isAckEliciting() = true

  override fun equals(other: Any?) = other is HandshakeDoneFrame

  override fun hashCode() = javaClass.hashCode()

  companion object {
    const val TYPE: Byte = 0x1e

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): HandshakeDoneFrame {
      assert(buffer.get() == TYPE)
      return HandshakeDoneFrame()
    }
  }
}
