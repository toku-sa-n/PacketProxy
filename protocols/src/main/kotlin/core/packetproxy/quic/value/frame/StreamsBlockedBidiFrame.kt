package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import packetproxy.quic.value.VariableLengthInteger

data class StreamsBlockedBidiFrame(val maxStreams: Long) : Frame() {
  override fun getBytes() = byteArrayOf(TYPE)

  override fun isAckEliciting() = true

  companion object {
    const val TYPE: Byte = 0x16

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): StreamsBlockedBidiFrame {
      assert(buffer.get() == TYPE)
      return StreamsBlockedBidiFrame(VariableLengthInteger.parse(buffer).value)
    }
  }
}
