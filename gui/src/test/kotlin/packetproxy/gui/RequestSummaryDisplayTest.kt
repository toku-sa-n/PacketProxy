package packetproxy.gui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RequestSummaryDisplayTest {
  @Test
  fun splitHttpUrl_separatesAuthorityAndPath() {
    assertEquals(
      "very.long.subdomain.example.com" to "/api/v1/users?x=1",
      splitHttpUrl("https://very.long.subdomain.example.com/api/v1/users?x=1"),
    )
  }

  @Test
  fun splitHttpUrl_withoutPath_usesRoot() {
    assertEquals("example.com" to "/", splitHttpUrl("http://example.com"))
  }

  @Test
  fun splitRequestSummary_httpMethodAndUrl() {
    assertEquals(
      RequestSummaryParts("GET", "example.com", "/hello"),
      splitRequestSummary("GET https://example.com/hello"),
    )
  }

  @Test
  fun splitRequestSummary_opaqueKeepsWholeTextInPath() {
    assertEquals(
      RequestSummaryParts("", "", "MQTT CONNECT client-1"),
      splitRequestSummary("MQTT CONNECT client-1"),
    )
  }

  @Test
  fun splitRequestSummary_empty() {
    assertEquals(RequestSummaryParts("", "", ""), splitRequestSummary(""))
  }
}
