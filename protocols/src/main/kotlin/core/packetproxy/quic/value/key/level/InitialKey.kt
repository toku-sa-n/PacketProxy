package packetproxy.quic.value.key.level

import at.favre.lib.crypto.HKDF
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.key.Key

class InitialKey(secret: ByteArray, key: ByteArray, iv: ByteArray, hp: ByteArray) :
  Key(secret, key, iv, hp) {
  companion object {
    private val STATIC_SALT_V1 =
      byteArrayOf(
        0x38,
        0x76,
        0x2c,
        0xf7.toByte(),
        0xf5.toByte(),
        0x59,
        0x34,
        0xb3.toByte(),
        0x4d,
        0x17,
        0x9a.toByte(),
        0xe6.toByte(),
        0xa4.toByte(),
        0xc8.toByte(),
        0x0c,
        0xad.toByte(),
        0xcc.toByte(),
        0xbb.toByte(),
        0x7f,
        0x0a,
      )

    @JvmStatic
    fun of(role: Constants.Role, destConnId: ConnectionId): InitialKey {
      val hkdf = HKDF.fromHmacSha256()
      val initialSecret = hkdf.extract(STATIC_SALT_V1, destConnId.bytes)
      val secret =
        if (role == Constants.Role.CLIENT) Key.hkdfExpandLabel(initialSecret, "client in", "", 32)
        else Key.hkdfExpandLabel(initialSecret, "server in", "", 32)
      val key = Key.of(secret)
      return InitialKey(key.secret, key.key, key.iv, key.hp)
    }
  }
}
