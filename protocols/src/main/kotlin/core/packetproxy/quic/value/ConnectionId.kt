package packetproxy.quic.value

import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Arrays
import org.apache.commons.codec.binary.Hex
import packetproxy.quic.utils.Constants

data class ConnectionId(val bytes: ByteArray) {
  override fun toString() = "ConnectionId([${Hex.encodeHexString(bytes)}])"

  override fun equals(other: Any?) =
    this === other || (other is ConnectionId && bytes.contentEquals(other.bytes))

  override fun hashCode() = Arrays.hashCode(bytes)

  companion object {
    @JvmStatic fun of(connId: ByteArray) = ConnectionId(connId)

    @JvmStatic
    fun generateRandom(): ConnectionId {
      val connId = ByteArray(Constants.CONNECTION_ID_SIZE)
      SecureRandom().nextBytes(connId)
      return ConnectionId(connId)
    }

    @JvmStatic
    fun parse(buffer: ByteBuffer, length: Long) =
      ConnectionId(SimpleBytes.parse(buffer, length).bytes)
  }
}
