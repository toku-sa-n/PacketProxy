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
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ModificationsPathApplyTest {
  private lateinit var database: Database
  private lateinit var modifications: Modifications

  @BeforeEach
  fun setUp() {
    var tempDb = Files.createTempFile("modifications_path_apply", ".sqlite3")
    database = Database()
    database.openAt(tempDb.toString())
    modifications = Modifications(database)
  }

  @Test
  fun replaceOnRequest_skipsWhenPathDoesNotMatch() {
    var mod =
      Modification(
        Modification.Direction.CLIENT_REQUEST,
        "secret",
        "REDACTED",
        Modification.Method.SIMPLE,
        null,
        "^/api/v1/",
      )
    modifications.create(mod.apply { setEnabled() })
    var packet = samplePacket()
    var original = "keep secret value".toByteArray()

    var result = modifications.replaceOnRequest(original, null, packet, "/other/path")
    assertEquals("keep secret value", String(result))
    assertFalse(packet.getModified())
  }

  @Test
  fun replaceOnRequest_appliesWhenPathMatches() {
    var mod =
      Modification(
        Modification.Direction.CLIENT_REQUEST,
        "secret",
        "REDACTED",
        Modification.Method.SIMPLE,
        null,
        "^/api/v1/",
      )
    modifications.create(mod.apply { setEnabled() })
    var packet = samplePacket()
    var original = "keep secret value".toByteArray()

    var result = modifications.replaceOnRequest(original, null, packet, "/api/v1/users")
    assertEquals("keep REDACTED value", String(result))
    assertTrue(packet.getModified())
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
