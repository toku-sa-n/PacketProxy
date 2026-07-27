package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import java.util.Arrays
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.VariableLengthInteger

data class ConnectionCloseFrame(
  val type: Byte,
  val errorCode: Long,
  val frameType: Long,
  val reasonPhrase: ByteArray,
) : Frame() {
  override fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(type)
    buffer.putLong(errorCode)
    if (type == 0x1c.toByte()) buffer.putLong(frameType)
    buffer.put(VariableLengthInteger.of(reasonPhrase.size.toLong()).bytes)
    buffer.put(reasonPhrase)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun isAckEliciting() = false

  val reasonPhraseString
    get() = String(reasonPhrase)

  override fun toString() =
    "ConnectionCloseFrame(errorCode=$errorCode, frameType=$frameType, reason=${String(reasonPhrase)})"

  override fun equals(other: Any?) =
    this === other ||
      (other is ConnectionCloseFrame &&
        type == other.type &&
        errorCode == other.errorCode &&
        frameType == other.frameType &&
        reasonPhrase.contentEquals(other.reasonPhrase))

  override fun hashCode() =
    31 * (31 * (31 * type.hashCode() + errorCode.hashCode()) + frameType.hashCode()) +
      Arrays.hashCode(reasonPhrase)

  companion object {
    @JvmStatic fun supportedTypes(): List<Byte> = listOf(0x1c.toByte(), 0x1d.toByte())

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): ConnectionCloseFrame {
      val type = buffer.get()
      assert(supportedTypes().any { it == type })
      val errorCode = VariableLengthInteger.parse(buffer).value
      val frameType = if (type == 0x1c.toByte()) VariableLengthInteger.parse(buffer).value else 0L
      val reasonPhraseLength = VariableLengthInteger.parse(buffer).value
      return ConnectionCloseFrame(
        type,
        errorCode,
        frameType,
        SimpleBytes.parse(buffer, reasonPhraseLength.toLong()).bytes,
      )
    }
  }
}
