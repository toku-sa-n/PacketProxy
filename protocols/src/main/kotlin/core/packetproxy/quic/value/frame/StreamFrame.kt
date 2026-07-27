package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import java.util.Arrays
import org.apache.commons.codec.binary.Hex
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.StreamId
import packetproxy.quic.value.VariableLengthInteger

data class StreamFrame(
  val streamId: StreamId,
  val offset: Long,
  val length: Long,
  val streamData: ByteArray,
  val finished: Boolean,
) : Frame() {
  private fun getType(): Byte {
    val offsetBit: Byte = if (offset > 0) 0x04 else 0x00
    val lengthBit: Byte = if (length > 0) 0x02 else 0x00
    val finishBit: Byte = if (finished) 0x01 else 0x00
    return (0x08 or offsetBit.toInt() or lengthBit.toInt() or finishBit.toInt()).toByte()
  }

  override fun toString() =
    "StreamFrame(streamId=$streamId, type=${getType().toInt() and 0xff}, offset=$offset, length=$length, data=[${Hex.encodeHexString(streamData)}])"

  override fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(getType())
    buffer.put(VariableLengthInteger.of(streamId.id).bytes)
    if (offset > 0) buffer.put(VariableLengthInteger.of(offset).bytes)
    if (length > 0) buffer.put(VariableLengthInteger.of(length).bytes)
    buffer.put(streamData)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun isAckEliciting() = true

  override fun equals(other: Any?) =
    this === other ||
      (other is StreamFrame &&
        streamId == other.streamId &&
        offset == other.offset &&
        length == other.length &&
        streamData.contentEquals(other.streamData) &&
        finished == other.finished)

  override fun hashCode(): Int {
    var result = streamId.hashCode()
    result = 31 * result + offset.hashCode()
    result = 31 * result + length.hashCode()
    result = 31 * result + Arrays.hashCode(streamData)
    return 31 * result + finished.hashCode()
  }

  companion object {
    @JvmStatic fun `is`(type: Byte) = supportedTypes().any { it == type }

    @JvmStatic
    fun supportedTypes(): List<Byte> =
      listOf(0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f).map { it.toByte() }

    private fun hasOffsetField(type: Byte) = (type.toInt() and 0x04) > 0

    private fun hasLengthField(type: Byte) = (type.toInt() and 0x02) > 0

    private fun hasFinishBit(type: Byte) = (type.toInt() and 0x01) > 0

    @JvmStatic
    fun of(
      streamId: StreamId,
      offset: Long,
      length: Long,
      streamData: ByteArray,
      finished: Boolean,
    ) = StreamFrame(streamId, offset, length, streamData, finished)

    @JvmStatic
    fun parse(buffer: ByteBuffer): StreamFrame {
      val type = buffer.get()
      assert(`is`(type))
      val streamId = StreamId.of(VariableLengthInteger.parse(buffer).value)
      val offset = if (hasOffsetField(type)) VariableLengthInteger.parse(buffer).value else 0L
      var length = if (hasLengthField(type)) VariableLengthInteger.parse(buffer).value else 0L
      val finished = hasFinishBit(type)
      val streamData: ByteArray
      if (length > 0) streamData = SimpleBytes.parse(buffer, length).bytes
      else {
        streamData = SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
        length = streamData.size.toLong()
      }
      return of(streamId, offset, length, streamData, finished)
    }
  }
}
