package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.VariableLengthInteger

data class ResetStreamFrame(
  val streamId: Long,
  val applicationErrorCode: Long,
  val finalSize: Long,
) : Frame() {
  override fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(TYPE)
    buffer.put(VariableLengthInteger.of(streamId).bytes)
    buffer.put(VariableLengthInteger.of(applicationErrorCode).bytes)
    buffer.put(VariableLengthInteger.of(finalSize).bytes)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun isAckEliciting() = true

  companion object {
    const val TYPE: Byte = 0x04

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): ResetStreamFrame {
      assert(buffer.get() == TYPE)
      return ResetStreamFrame(
        VariableLengthInteger.parse(buffer).value,
        VariableLengthInteger.parse(buffer).value,
        VariableLengthInteger.parse(buffer).value,
      )
    }
  }
}
