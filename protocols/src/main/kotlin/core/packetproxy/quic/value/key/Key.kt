package packetproxy.quic.value.key

import at.favre.lib.crypto.HKDF
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Hex

open class Key(val secret: ByteArray, val key: ByteArray, val iv: ByteArray, val hp: ByteArray) {
  @Throws(Exception::class)
  fun getMaskForHeaderProtection(sample: ByteArray): ByteArray {
    val keySpec = SecretKeySpec(hp, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    return cipher.doFinal(sample)
  }

  @Throws(Exception::class)
  fun aesGCM(
    cipherMode: Int,
    packetNumber: ByteArray,
    payload: ByteArray,
    associatedData: ByteArray,
  ): ByteArray {
    val nonce = getNonce(packetNumber)
    val keySpec = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(cipherMode, keySpec, GCMParameterSpec(128, nonce))
    cipher.updateAAD(associatedData)
    return cipher.doFinal(payload)
  }

  @Throws(Exception::class)
  fun decryptPayload(
    packetNumber: ByteArray,
    encryptPayload: ByteArray,
    associatedData: ByteArray,
  ) = aesGCM(Cipher.DECRYPT_MODE, packetNumber, encryptPayload, associatedData)

  @Throws(Exception::class)
  fun encryptPayload(packetNumber: ByteArray, payload: ByteArray, associatedData: ByteArray) =
    aesGCM(Cipher.ENCRYPT_MODE, packetNumber, payload, associatedData)

  private fun getNonce(packetNumber: ByteArray): ByteArray {
    val nonce = ByteArray(12)
    for (i in 0 until 12) {
      nonce[i] = iv[i]
      if (i >= nonce.size - packetNumber.size) {
        nonce[i] =
          (nonce[i].toInt() xor packetNumber[i - (nonce.size - packetNumber.size)].toInt()).toByte()
      }
    }
    return nonce
  }

  override fun toString() =
    "Key(secret=${Hex.encodeHexString(secret)}, key=${Hex.encodeHexString(key)}, iv=${Hex.encodeHexString(iv)}, hp=${Hex.encodeHexString(hp)})"

  companion object {
    @JvmField
    val STATIC_SALT_V1 =
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
    fun hkdfExpandLabel(
      secret: ByteArray,
      labelStr: String,
      contextStr: String,
      length: Int,
    ): ByteArray = hkdfExpandLabel(secret, labelStr, contextStr, length.toShort())

    fun hkdfExpandLabel(
      secret: ByteArray,
      labelStr: String,
      contextStr: String,
      length: Short,
    ): ByteArray {
      val label = "tls13 $labelStr".toByteArray()
      val context = contextStr.toByteArray()
      val hkdfLabel = ByteBuffer.allocate(2 + 1 + label.size + 1 + context.size)
      hkdfLabel.putShort(length)
      hkdfLabel.put(label.size.toByte())
      hkdfLabel.put(label)
      hkdfLabel.put(context.size.toByte())
      hkdfLabel.put(context)
      return HKDF.fromHmacSha256().expand(secret, hkdfLabel.array(), length.toInt())
    }

    @JvmStatic
    fun of(secret: ByteArray): Key {
      val key = hkdfExpandLabel(secret, "quic key", "", 16)
      val iv = hkdfExpandLabel(secret, "quic iv", "", 12)
      val hp = hkdfExpandLabel(secret, "quic hp", "", 16)
      return Key(secret, key, iv, hp)
    }
  }
}
