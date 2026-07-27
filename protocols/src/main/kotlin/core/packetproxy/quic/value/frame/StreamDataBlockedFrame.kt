package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import packetproxy.quic.value.VariableLengthInteger

data class StreamDataBlockedFrame(val streamId: Long, val maxStreamData: Long) : Frame() {
  override fun getBytes() = byteArrayOf(TYPE)

  override fun isAckEliciting() = true

  companion object {
    const val TYPE: Byte = 0x15

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): StreamDataBlockedFrame {
      assert(buffer.get() == TYPE)
      return StreamDataBlockedFrame(
        VariableLengthInteger.parse(buffer).value,
        VariableLengthInteger.parse(buffer).value,
      )
    }
  }
}
