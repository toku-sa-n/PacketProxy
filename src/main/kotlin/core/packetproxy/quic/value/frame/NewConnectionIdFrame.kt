package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.FixedLengthPrecededBytes
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.Token
import packetproxy.quic.value.VariableLengthInteger

data class NewConnectionIdFrame(
  val sequenceNumber: Long,
  val retirePriorTo: Long,
  val connectionId: ConnectionId,
  val stateResetToken: Token,
) : Frame() {
  override fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(1500)
    buffer.put(TYPE)
    buffer.put(VariableLengthInteger.of(sequenceNumber).bytes)
    buffer.put(VariableLengthInteger.of(retirePriorTo).bytes)
    buffer.put(FixedLengthPrecededBytes.of(connectionId.bytes).serialize())
    buffer.put(stateResetToken.bytes)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }

  override fun isAckEliciting() = true

  companion object {
    const val TYPE: Byte = 0x18

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): NewConnectionIdFrame {
      assert(buffer.get() == TYPE)
      return NewConnectionIdFrame(
        VariableLengthInteger.parse(buffer).value,
        VariableLengthInteger.parse(buffer).value,
        ConnectionId.of(FixedLengthPrecededBytes.parse(buffer).bytes),
        Token.of(SimpleBytes.parse(buffer, 16).bytes),
      )
    }
  }
}
