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

  @Test
  fun updatePersistedSummaries_updatesColumnsWithoutRewritingBlobs() {
    var packet = sampleClientPacket()
    var payload = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
    packet.setReceivedData(payload)
    packet.setDecodedData(payload)
    packet.setModifiedData(payload)
    packets.updateSync(packet)
    var id = packet.getId()

    packets.updatePersistedSummaries(
      id,
      "GET https://example.com/api",
      "",
      payload.size,
      notify = false,
    )

    var reloaded = requireNotNull(packets.query(id))
    assertEquals("GET https://example.com/api", reloaded.getSummarizedRequestColumn())
    assertEquals("", reloaded.getSummarizedResponseColumn())
    assertEquals(payload.size, reloaded.getDisplayLength())
    assertTrue(reloaded.getReceivedData().contentEquals(payload))
    assertTrue(reloaded.getDecodedData().contentEquals(payload))
  }

  @Test
  fun updatePersistedSummaries_notifyFalse_doesNotFirePropertyChange() {
    var packet = sampleClientPacket()
    var payload = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
    packet.setDecodedData(payload)
    packets.updateSync(packet)
    var id = packet.getId()

    var notified = false
    packets.addPropertyChangeListener {
      if (it.newValue == id) {
        notified = true
      }
    }

    packets.updatePersistedSummaries(id, "GET https://example.com/api", "", payload.size, false)

    assertTrue(!notified)
    var meta = requireNotNull(packets.queryByIdMetadata(id))
    assertEquals("GET https://example.com/api", meta.getSummarizedRequestColumn())
  }

  @Test
  fun updatePersistedSummaries_acceptsSpecialCharactersInSummary() {
    var packet = sampleClientPacket()
    var payload = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
    packet.setDecodedData(payload)
    packets.updateSync(packet)
    var id = packet.getId()
    var summary = "GET https://example.com/o'brien?q=%2bfoo&x=1"

    packets.updatePersistedSummaries(id, summary, "", payload.size, notify = false)

    var meta = requireNotNull(packets.queryByIdMetadata(id))
    assertEquals(summary, meta.getSummarizedRequestColumn())
  }

  @Test
  fun updatePersistedSummaries_withSqlCommentPayload_doesNotOverwriteOtherRows() {
    var payload = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
    var first = sampleClientPacket()
    first.setDecodedData(payload)
    packets.updateSync(first)
    var firstId = first.getId()
    packets.updatePersistedSummaries(
      firstId,
      "GET https://example.com/first",
      "",
      payload.size,
      notify = false,
    )

    var second = sampleClientPacket()
    second.setDecodedData(payload)
    packets.updateSync(second)
    var secondId = second.getId()
    var evilSummary = "POST https://api.example.com/live/%22--%3e'--%3e%60--%3e"
    packets.updatePersistedSummaries(secondId, evilSummary, "", payload.size, notify = false)

    assertEquals(
      "GET https://example.com/first",
      requireNotNull(packets.queryByIdMetadata(firstId)).getSummarizedRequestColumn(),
    )
    assertEquals(
      evilSummary,
      requireNotNull(packets.queryByIdMetadata(secondId)).getSummarizedRequestColumn(),
    )
  }

  @Test
  fun clearPersistedSummariesOnce_clearsSummariesThenSkipsSecondRun() {
    var payload = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
    var packet = sampleClientPacket()
    packet.setDecodedData(payload)
    packets.updateSync(packet)
    var id = packet.getId()
    packets.updatePersistedSummaries(
      id,
      "GET https://example.com/corrupt",
      "200 OK",
      payload.size,
      notify = false,
    )
    assertEquals(
      "GET https://example.com/corrupt",
      requireNotNull(packets.queryByIdMetadata(id)).getSummarizedRequestColumn(),
    )

    var dao = database.createTable(Packet::class.java)
    dao.executeRaw("DELETE FROM packetproxy_migrations WHERE name = ?", "summary_selectarg_v1")
    packets = Packets(database, false)

    var cleared = requireNotNull(packets.queryByIdMetadata(id))
    assertTrue(cleared.getSummarizedRequestColumn().isNullOrEmpty())
    assertTrue(cleared.getSummarizedResponseColumn().isNullOrEmpty())
    assertTrue(
      dao
        .queryRaw("SELECT 1 FROM packetproxy_migrations WHERE name = ?", "summary_selectarg_v1")
        .results
        .isNotEmpty()
    )

    packets.updatePersistedSummaries(
      id,
      "GET https://example.com/repaired",
      "",
      payload.size,
      notify = false,
    )
    packets = Packets(database, false)
    assertEquals(
      "GET https://example.com/repaired",
      requireNotNull(packets.queryByIdMetadata(id)).getSummarizedRequestColumn(),
    )
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
