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
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PacketBlobAliasTest {
  @Test
  fun compactForPersist_aliasesIdenticalStages() {
    val packet =
      Packet(
        8080,
        InetSocketAddress("127.0.0.1", 12345),
        InetSocketAddress("127.0.0.1", 443),
        "example.com",
        true,
        "HTTP",
        "",
        Packet.Direction.CLIENT,
        1,
        1L,
      )
    val payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
    packet.setReceivedData(payload)
    packet.setDecodedData(payload.copyOf())
    packet.setModifiedData(payload.copyOf())
    packet.setSentData(payload.copyOf())

    packet.compactForPersist()

    assertTrue((packet.getBlobFlags() and Packet.FLAG_DECODED_ALIASES_RECEIVED) != 0)
    assertTrue((packet.getBlobFlags() and Packet.FLAG_MODIFIED_ALIASES_DECODED) != 0)
    assertTrue((packet.getBlobFlags() and Packet.FLAG_SENT_ALIASES_MODIFIED) != 0)
    assertTrue(packet.getDecodedData().contentEquals(payload))
    assertTrue(packet.getModifiedData().contentEquals(payload))
    assertTrue(packet.getSentData().contentEquals(payload))
  }

  @Test
  fun compactForPersist_keepsDistinctModified() {
    val packet =
      Packet(
        8080,
        InetSocketAddress("127.0.0.1", 12345),
        InetSocketAddress("127.0.0.1", 443),
        "example.com",
        true,
        "HTTP",
        "",
        Packet.Direction.CLIENT,
        1,
        1L,
      )
    val received = "AAA".toByteArray()
    val modified = "BBB".toByteArray()
    packet.setReceivedData(received)
    packet.setDecodedData(received.copyOf())
    packet.setModifiedData(modified)
    packet.setSentData(modified.copyOf())

    packet.compactForPersist()

    assertEquals(
      Packet.FLAG_DECODED_ALIASES_RECEIVED,
      packet.getBlobFlags() and Packet.FLAG_DECODED_ALIASES_RECEIVED,
    )
    assertEquals(0, packet.getBlobFlags() and Packet.FLAG_MODIFIED_ALIASES_DECODED)
    assertTrue((packet.getBlobFlags() and Packet.FLAG_SENT_ALIASES_MODIFIED) != 0)
    assertTrue(packet.getModifiedData().contentEquals(modified))
    assertTrue(packet.getSentData().contentEquals(modified))
  }
}
