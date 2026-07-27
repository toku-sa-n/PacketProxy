/*
 * Copyright 2019 shioshiota
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

import kotlin.test.assertEquals
import net.arnx.jsonic.JSON
import org.junit.jupiter.api.Test

class GRPCTest {
  @Test
  fun testGRPCWebRequest() {
    assertRoundTrip("AAAAAA4KDHRlc3QgbWVzc2FnZQ==")
  }

  @Test
  fun testGRPCWebResponse() {
    assertRoundTrip(
      "AAAAAA4KDHRlc3QgbWVzc2FnZQ==gAAAAbxncnBjLXN0YXR1czowDQpncnBjLW1lc3NhZ2U6T0sNCngtdXNlci1hZ2VudDpncnBjLXdlYi1qYXZhc2NyaXB0LzAuMQ0Kb3JpZ2luOmh0dHA6Ly91YnVudHU6ODA4MQ0KY3VzdG9tLWhlYWRlci0xOnZhbHVlMQ0KdXNlci1hZ2VudDpNb3ppbGxhLzUuMCAoWDExOyBMaW51eCB4ODZfNjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS83OC4wLjM5MDQuNzAgU2FmYXJpLzUzNy4zNg0KYWNjZXB0OmFwcGxpY2F0aW9uL2dycGMtd2ViLXRleHQNCngtZ3JwYy13ZWI6MQ0KcmVmZXJlcjpodHRwOi8vdWJ1bnR1OjgwODEvZWNob3Rlc3QuaHRtbA0KYWNjZXB0LWxhbmd1YWdlOmphLGVuLVVTO3E9MC45LGVuO3E9MC44DQp4LWZvcndhcmRlZC1wcm90bzpodHRwDQp4LXJlcXVlc3QtaWQ6ODVlZTFlNjItOTA4My00NzY0LThjNDQtYTBmMWJjYjM4MzhkDQo="
    )
  }

  @Test
  fun testLongGRPCWebRequest() {
    assertRoundTrip(encodeDataFrame("a".repeat(1200)))
  }

  @Test
  fun testLongGRPCWebResponse() {
    assertRoundTrip(encodeDataFrame("a".repeat(1200)) + encodeTrailerFrame())
  }

  private fun assertRoundTrip(data: String) {
    val messages: List<Map<String, Any?>> =
      JSON.decode(JSON.encode(GRPCMessage.decodeTextMessages(data)))
    assertEquals(data, GRPCMessage.encodeTextMessages(messages))
  }

  private fun encodeDataFrame(message: String): String {
    val json = mapOf("type" to 0, "message" to mapOf("0001:0000:String" to message))
    return GRPCMessage.encodeTextMessages(listOf(json))
  }

  private fun encodeTrailerFrame(): String {
    val json =
      mapOf(
        "type" to 128,
        "message" to mapOf("headers" to listOf("grpc-status:0", "grpc-message:OK")),
      )
    return GRPCMessage.encodeTextMessages(listOf(json))
  }
}
