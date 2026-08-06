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
import java.nio.file.Files
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class PacketSummaryBackfillTest {
  private lateinit var database: Database
  private lateinit var packets: Packets

  private val summarizer =
    object : PacketSummarizer {
      override fun summarizeRequest(encoderName: String?, alpn: String?, packet: Packet): String {
        if (packet.getDecodedData().isEmpty() && packet.getModifiedData().isEmpty()) {
          return ""
        }
        return "GET https://example.com/api"
      }

      override fun summarizeResponse(encoderName: String?, alpn: String?, packet: Packet): String =
        "200 OK"
    }

  @BeforeEach
  fun setUp() {
    var tempDb = Files.createTempFile("packet_summary_backfill_test", ".sqlite3")
    database = Database()
    database.openAt(tempDb.toString())
    packets = Packets(database, false)
  }

  @Test
  fun getSummarizedRequest_fallsBackToSummarizerWhenPersistedEmpty() {
    var packet = sampleClientPacket()
    var payload = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
    packet.setDecodedData(payload)
    packet.setSummarizedRequestColumn("")

    var summary = packet.getSummarizedRequest(summarizer)

    assertEquals("GET https://example.com/api", summary)
  }

  @Test
  fun refreshPersistedSummaries_backfillsEmptyRequestSummary() {
    var packet = sampleClientPacket()
    var payload = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
    packet.setReceivedData(payload)
    packet.setDecodedData(payload)
    packet.setModifiedData(payload)
    packets.updateSync(packet)
    var id = packet.getId()

    // Simulate pre-summarized_request rows: clear persisted summary after insert.
    packet.setSummarizedRequestColumn("")
    packet.setDisplayLength(0)
    packets.updateSync(packet)

    var meta = requireNotNull(packets.queryByIdMetadata(id))
    assertTrue(meta.getSummarizedRequestColumn().isNullOrEmpty())

    var full = requireNotNull(packets.query(id))
    full.refreshPersistedSummaries(summarizer)
    packets.updateSync(full)

    var reloaded = requireNotNull(packets.queryByIdMetadata(id))
    assertEquals("GET https://example.com/api", reloaded.getSummarizedRequestColumn())
    assertTrue(reloaded.getDisplayLength() > 0)
    assertEquals("GET https://example.com/api", reloaded.getSummarizedRequest(summarizer))
  }

  private fun sampleClientPacket(): Packet {
    var client = InetSocketAddress("127.0.0.1", 12345)
    var server = InetSocketAddress("127.0.0.1", 443)
    return Packet(
      8080,
      client,
      server,
      "example.com",
      true,
      "HTTP",
      "",
      Packet.Direction.CLIENT,
      1,
      1L,
    )
  }
}
