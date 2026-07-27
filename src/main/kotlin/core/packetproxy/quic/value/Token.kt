package packetproxy.quic.value

import java.security.SecureRandom
import java.util.Arrays
import org.apache.commons.codec.binary.Hex

class Token private constructor(val bytes: ByteArray) {
  override fun toString() = "Token([${Hex.encodeHexString(bytes)}])"

  override fun equals(other: Any?) =
    this === other || (other is Token && bytes.contentEquals(other.bytes))

  override fun hashCode() = Arrays.hashCode(bytes)

  companion object {
    @JvmStatic fun of(token: ByteArray) = Token(token)

    @JvmStatic
    fun generateRandom(size: Int): Token {
      val token = ByteArray(size)
      SecureRandom().nextBytes(token)
      return Token(token)
    }
  }
}
