/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.common

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.binary.Hex

class CryptUtils {
  companion object {
    @JvmStatic fun md5(target: String): String = Hex.encodeHexString(md5(target.toByteArray()))

    @JvmStatic
    fun md5(target: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(target)

    @JvmStatic fun sha1(target: String): String = Hex.encodeHexString(sha1(target.toByteArray()))

    @JvmStatic
    fun sha1(target: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(target)

    @JvmStatic
    fun sha256(target: String): String = Hex.encodeHexString(sha256(target.toByteArray()))

    @JvmStatic
    fun sha256(target: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(target)

    @JvmStatic
    fun encryptECBPKCS5(key: ByteArray, cipherText: ByteArray): String =
      encryptECB("PKCS5", key, cipherText)

    @JvmStatic
    fun encryptECBISO10126(key: ByteArray, cipherText: ByteArray): String =
      encryptECB("ISO10126", key, cipherText)

    @JvmStatic
    fun encryptCBCPKCS5(key: ByteArray, iv: ByteArray?, cipherText: ByteArray): String =
      encryptCBC("PKCS5", key, iv, cipherText)

    @JvmStatic
    fun encryptCBCISO10126(key: ByteArray, iv: ByteArray?, cipherText: ByteArray): String =
      encryptCBC("ISO10126", key, iv, cipherText)

    @JvmStatic
    fun decryptECBPKCS5(key: ByteArray, cipherText: ByteArray): String =
      String(decryptECB("PKCS5", key, cipherText), Charsets.UTF_8)

    @JvmStatic
    fun decryptECBISO10126(key: ByteArray, cipherText: ByteArray): String =
      String(decryptECB("ISO10126", key, cipherText), Charsets.UTF_8)

    @JvmStatic
    fun decryptCBCPKCS5(key: ByteArray, cipherText: ByteArray): String =
      decryptCBC("PKCS5", key, cipherText)

    @JvmStatic
    fun decryptCBCISO10126(key: ByteArray, cipherText: ByteArray): String =
      decryptCBC("ISO10126", key, cipherText)

    @JvmStatic
    fun encryptECB(key: ByteArray, cipherText: ByteArray): String {
      val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
      cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
      return String(Base64.encodeBase64(cipher.doFinal(cipherText)))
    }

    @JvmStatic
    fun encryptECB(padding: String, key: ByteArray, cipherText: ByteArray): String {
      val cipher = Cipher.getInstance("AES/ECB/${padding}Padding")
      cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
      return String(Base64.encodeBase64(cipher.doFinal(cipherText)))
    }

    @JvmStatic
    fun encryptCBC(padding: String, key: ByteArray, iv: ByteArray?, input: ByteArray): String {
      val cipher = Cipher.getInstance("AES/CBC/${padding}Padding")
      val actualIv = iv ?: cipher.iv
      cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(actualIv))
      val encrypted = cipher.doFinal(input)
      val result = ByteArray(actualIv.size + encrypted.size)
      System.arraycopy(actualIv, 0, result, 0, actualIv.size)
      System.arraycopy(encrypted, 0, result, actualIv.size, encrypted.size)
      return toHex(result)
    }

    @JvmStatic
    fun decrypt(key: ByteArray, originalText: ByteArray): ByteArray {
      val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
      cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
      return cipher.doFinal(originalText)
    }

    @JvmStatic
    fun decryptECB(padding: String, key: ByteArray, originalText: ByteArray): ByteArray {
      val cipher = Cipher.getInstance("AES/ECB/${padding}Padding")
      cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
      return cipher.doFinal(originalText)
    }

    @JvmStatic
    fun decryptCBC(padding: String, key: ByteArray, input: ByteArray): String {
      val cipher = Cipher.getInstance("AES/CBC/${padding}Padding")
      val iv = input.copyOfRange(0, 16)
      val cipherByte = input.copyOfRange(16, input.size)
      cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
      return String(cipher.doFinal(cipherByte), Charsets.UTF_8)
    }

    @JvmStatic
    fun toByte(hex: String): ByteArray =
      ByteArray(hex.length / 2) { index ->
        hex.substring(index * 2, (index + 1) * 2).toInt(16).toByte()
      }

    @JvmStatic
    fun toHex(bytes: ByteArray): String =
      buildString(bytes.size * 2) {
        bytes.forEach {
          val value = it.toInt() and 0xff
          if (value < 0x10) append("0")
          append(value.toString(16))
        }
      }
  }
}
