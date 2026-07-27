package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import packetproxy.quic.value.VariableLengthInteger

data class StreamsBlockedUniFrame(val maxStreams: Long) : Frame() {
  override fun getBytes() = byteArrayOf(TYPE)

  override fun isAckEliciting() = true

  companion object {
    const val TYPE: Byte = 0x17

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): StreamsBlockedUniFrame {
      assert(buffer.get() == TYPE)
      return StreamsBlockedUniFrame(VariableLengthInteger.parse(buffer).value)
    }
  }
}
