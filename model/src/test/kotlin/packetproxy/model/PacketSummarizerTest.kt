/*
 * Copyright 2026 DeNA Co., Ltd.
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
package packetproxy.model

import java.net.InetSocketAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class PacketSummarizerTest {
  @Test
  fun noOpSummarizer_returnsEmptyStrings() {
    var summarizer: PacketSummarizer = NoOpPacketSummarizer()
    var packet = samplePacket("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
    assertEquals("", summarizer.summarizeRequest("HTTP", "http/1.1", packet))
    assertEquals("", summarizer.summarizeResponse("HTTP", "http/1.1", packet))
  }

  @Test
  fun customSummarizer_delegatesToImplementation() {
    var summarizer =
      object : PacketSummarizer {
        override fun summarizeRequest(encoderName: String?, alpn: String?, packet: Packet): String =
          "REQ:${encoderName}:${String(packet.getDecodedData()).lineSequence().first()}"

        override fun summarizeResponse(
          encoderName: String?,
          alpn: String?,
          packet: Packet,
        ): String = "RES:${encoderName}"
      }
    var packet = samplePacket("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
    assertEquals("REQ:HTTP:GET /api HTTP/1.1", summarizer.summarizeRequest("HTTP", null, packet))
    assertEquals("RES:HTTP", summarizer.summarizeResponse("HTTP", null, packet))
  }

  private fun samplePacket(payload: ByteArray): Packet {
    var client = InetSocketAddress("127.0.0.1", 12345)
    var server = InetSocketAddress("127.0.0.1", 80)
    var packet =
      Packet(8080, client, server, "example.com", false, "HTTP", "", Packet.Direction.CLIENT, 1, 1L)
    packet.setDecodedData(payload)
    return packet
  }
}
