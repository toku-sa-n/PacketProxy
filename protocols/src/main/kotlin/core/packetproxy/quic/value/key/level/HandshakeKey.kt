package packetproxy.quic.value.key.level

import packetproxy.quic.value.key.Key

class HandshakeKey(secret: ByteArray, key: ByteArray, iv: ByteArray, hp: ByteArray) :
  Key(secret, key, iv, hp) {
  companion object {
    @JvmStatic
    fun of(secret: ByteArray): HandshakeKey {
      val key = Key.of(secret)
      return HandshakeKey(key.secret, key.key, key.iv, key.hp)
    }
  }
}
