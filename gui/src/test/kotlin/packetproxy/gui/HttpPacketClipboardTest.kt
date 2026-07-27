package packetproxy.gui

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import packetproxy.model.Packet
import packetproxy.util.CharSetUtility

class HttpPacketClipboardTest {
  @BeforeEach
  fun setUp() {
    val utility = CharSetUtility.getInstance()
    val charSetField = CharSetUtility::class.java.getDeclaredField("charSetValue")
    charSetField.isAccessible = true
    charSetField.set(utility, "UTF-8")
    val isAutoField = CharSetUtility::class.java.getDeclaredField("autoFlag")
    isAutoField.isAccessible = true
    isAutoField.setBoolean(utility, false)
  }

  @Test
  fun formatMethodUrlBody_returnsTabSeparatedMethodUrlAndBody() {
    val data =
      """
      GET /hello HTTP/1.1
      Host: example.com

      request-body
      """
        .trimIndent()
        .replace("\n", "\r\n")
        .toByteArray()
    val packet =
      Packet(
        8080,
        "127.0.0.1",
        12345,
        "93.184.216.34",
        443,
        "example.com",
        true,
        "HTTP",
        "",
        Packet.Direction.CLIENT,
        1,
        1L,
      )

    val result = formatMethodUrlBody(data, packet)

    assertThat(result).isEqualTo("GET\thttps://example.com/hello\trequest-body")
  }
}
