package packetproxy.quic.value.frame

import java.nio.ByteBuffer
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.Token
import packetproxy.quic.value.VariableLengthInteger
import packetproxy.util.Logging.err

data class NewTokenFrame(val token: Token) : Frame() {
  override fun getBytes() = byteArrayOf(TYPE)

  override fun isAckEliciting() = true

  companion object {
    const val TYPE: Byte = 0x7

    @JvmStatic fun supportedTypes(): List<Byte> = listOf(TYPE)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): NewTokenFrame {
      assert(buffer.get() == TYPE)
      val tokenLength = VariableLengthInteger.parse(buffer).value
      if (tokenLength == 0L) err("NewTokenFrame: error: FRAME_ENCODING_ERROR")
      return NewTokenFrame(Token.of(SimpleBytes.parse(buffer, tokenLength.toLong()).bytes))
    }
  }
}
