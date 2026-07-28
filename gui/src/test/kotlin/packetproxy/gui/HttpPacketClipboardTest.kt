package packetproxy.gui

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import packetproxy.model.CharSets
import packetproxy.model.Database
import packetproxy.model.Packet
import packetproxy.util.CharSetUtility

class HttpPacketClipboardTest {
  private lateinit var charSetUtility: CharSetUtility

  @BeforeEach
  fun setUp() {
    val database = Database()
    database.createDB()
    charSetUtility = CharSetUtility(CharSets(database))
    charSetUtility.setCharSet("UTF-8")
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

    val result = formatMethodUrlBody(data, packet, charSetUtility)

    assertThat(result).isEqualTo("GET\thttps://example.com/hello\trequest-body")
  }
}
