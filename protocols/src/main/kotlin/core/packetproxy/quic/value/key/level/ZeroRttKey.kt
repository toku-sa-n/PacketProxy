package packetproxy.quic.value.key.level

import packetproxy.quic.value.key.Key

class ZeroRttKey(secret: ByteArray, key: ByteArray, iv: ByteArray, hp: ByteArray) :
  Key(secret, key, iv, hp) {
  companion object {
    @JvmStatic
    fun of(secret: ByteArray): ZeroRttKey {
      val key = Key.of(secret)
      return ZeroRttKey(key.secret, key.key, key.iv, key.hp)
    }
  }
}
