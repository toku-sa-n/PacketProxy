package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.VariableLengthInteger

data class MaxDataFrame(val maxData: Long) : Frame() {
  override fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(TYPE)
    buffer.put(VariableLengthInteger.of(maxData).bytes)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun isAckEliciting() = true

  companion object {
    const val TYPE: Byte = 0x10

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): MaxDataFrame {
      buffer.get()
      return MaxDataFrame(VariableLengthInteger.parse(buffer).value)
    }
  }
}
