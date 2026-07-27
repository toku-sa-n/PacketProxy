package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import java.util.Arrays
import org.apache.commons.codec.binary.Hex
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.VariableLengthInteger

data class CryptoFrame(val offset: Long, val data: ByteArray) : Frame() {
  override fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(TYPE)
    buffer.put(VariableLengthInteger.of(offset).bytes)
    buffer.put(VariableLengthInteger.of(data.size.toLong()).bytes)
    buffer.put(data)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun toString() =
    "CryptFrame(offset=$offset, length=${data.size}, data=${Hex.encodeHexString(data)})"

  override fun isAckEliciting() = true

  override fun equals(other: Any?) =
    this === other ||
      (other is CryptoFrame && offset == other.offset && data.contentEquals(other.data))

  override fun hashCode() = 31 * offset.hashCode() + Arrays.hashCode(data)

  companion object {
    const val TYPE: Byte = 0x06

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): CryptoFrame {
      assert(buffer.get() == TYPE)
      val offset = VariableLengthInteger.parse(buffer).value
      val length = VariableLengthInteger.parse(buffer).value
      return CryptoFrame(offset, SimpleBytes.parse(buffer, length).bytes)
    }
  }
}
