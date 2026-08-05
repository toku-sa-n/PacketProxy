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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class PacketsUpdateTest {
  private lateinit var database: Database
  private lateinit var packets: Packets

  @BeforeEach
  fun setUp() {
    var tempDb = Files.createTempFile("packets_update_test", ".sqlite3")
    database = Database()
    database.openAt(tempDb.toString())
    packets = Packets(database, false)
  }

  @Test
  fun updateContentType_updatesOnlyMetadata() {
    var packet = samplePacket()
    packet.setReceivedData(byteArrayOf(1, 2, 3, 4))
    packet.setDecodedData(byteArrayOf(5, 6, 7, 8))
    packets.updateSync(packet)
    var id = packet.getId()
    assertTrue(id > 0)

    packets.updateContentType(id, "text/plain")
    var loaded = requireNotNull(packets.query(id))
    assertEquals("text/plain", loaded.getContentType())
    assertTrue(loaded.getReceivedData().contentEquals(byteArrayOf(1, 2, 3, 4)))
    assertTrue(loaded.getDecodedData().contentEquals(byteArrayOf(5, 6, 7, 8)))
  }

  @Test
  fun update_coalescesAndPersistsInBatch() {
    var packet = samplePacket()
    packet.setDecodedData("hello".toByteArray())
    packets.updateSync(packet)
    var id = packet.getId()

    var latch = CountDownLatch(1)
    packets.addPropertyChangeListener {
      if (it.newValue == id) {
        latch.countDown()
      }
    }

    packet.setDecodedData("world".toByteArray())
    packet.setSentData("world".toByteArray())
    packets.update(packet)
    packet.setContentType("application/json")
    packets.update(packet)

    assertTrue(latch.await(3, TimeUnit.SECONDS))
    // Allow flush executor to settle
    Thread.sleep(100)
    var loaded = requireNotNull(packets.query(id))
    assertEquals("application/json", loaded.getContentType())
    assertEquals("world", String(loaded.getDecodedData()))
    assertEquals("world", String(loaded.getSentData()))
  }

  private fun samplePacket(): Packet {
    var client = InetSocketAddress("127.0.0.1", 12345)
    var server = InetSocketAddress("127.0.0.1", 80)
    return Packet(
      8080,
      client,
      server,
      "example.com",
      false,
      "HTTP",
      "",
      Packet.Direction.CLIENT,
      1,
      1L,
    )
  }
}
