package packetproxy.quic.value.key.level

import packetproxy.quic.value.key.Key

class ApplicationKey(secret: ByteArray, key: ByteArray, iv: ByteArray, hp: ByteArray) :
  Key(secret, key, iv, hp) {
  companion object {
    @JvmStatic
    fun of(secret: ByteArray): ApplicationKey {
      val key = Key.of(secret)
      return ApplicationKey(key.secret, key.key, key.iv, key.hp)
    }
  }
}
