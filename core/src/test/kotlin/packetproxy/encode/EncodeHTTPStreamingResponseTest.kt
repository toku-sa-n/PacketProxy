package packetproxy.encode

import java.nio.file.Files
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import packetproxy.common.UniqueID
import packetproxy.model.Database
import packetproxy.model.Packets

class EncodeHTTPStreamingResponseTest {
  private lateinit var packets: Packets

  @BeforeEach
  fun setUp() {
    var tempDb = Files.createTempFile("streaming_response_test", ".sqlite3")
    var database = Database()
    database.openAt(tempDb.toString())
    packets = Packets(database, false)
  }

  @Test
  fun attachStreamingHelpers_enablesHttp1DelimiterChecks() {
    var encoder = EncodeHTTPStreamingResponse("http/1.1")
    encoder.attachStreamingHelpers(packets, UniqueID())

    var request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
    assertEquals(request.size, encoder.checkRequestDelimiter(request))
  }

  @Test
  fun attachStreamingHelpers_enablesHttp2DelimiterChecks() {
    var encoder = EncodeHTTPStreamingResponse("h2")
    encoder.attachStreamingHelpers(packets, UniqueID())
    assertNotNull(encoder)
    // Incomplete frame returns -1 rather than NPE
    assertEquals(-1, encoder.checkRequestDelimiter(ByteArray(0)))
  }
}
