package packetproxy.common

import java.nio.charset.StandardCharsets
import org.apache.commons.codec.binary.Base64
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class CryptUtilsTest {
  @Test
  fun decryptECBPKCS5ReturnsUtf8StringNotByteArrayToString() {
    val key = "0123456789abcdef".toByteArray(StandardCharsets.UTF_8)
    val plain = "hello-packetproxy"
    val encrypted = CryptUtils.encryptECBPKCS5(key, plain.toByteArray(StandardCharsets.UTF_8))
    val cipherBytes = Base64.decodeBase64(encrypted)
    val decrypted = CryptUtils.decryptECBPKCS5(key, cipherBytes)
    assertEquals(plain, decrypted)
  }
}
