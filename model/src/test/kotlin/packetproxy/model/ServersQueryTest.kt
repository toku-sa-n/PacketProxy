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

import java.nio.file.Files
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ServersQueryTest {
  private lateinit var database: Database
  private lateinit var servers: Servers

  @BeforeEach
  fun setUp() {
    val tempDb = Files.createTempFile("servers_query_test", ".sqlite3")
    database = Database()
    database.openAt(tempDb.toString())
    servers = Servers(database)
  }

  @Test
  fun queryByHostNameAndPort_returnsNullWhenUnresolved() {
    assertNull(servers.queryByHostNameAndPort("missing.example", 443))
  }

  @Test
  fun queryByHostNameAndPort_returnsServerAndUsesDelimitedCacheKey() {
    val server = Server("example.com", 443, "HTTP")
    servers.create(server)

    val found = servers.queryByHostNameAndPort("example.com", 443)
    assertNotNull(found)
    assertEquals(server.getId(), found!!.getId())

    // Second lookup should hit cache and still return the same id
    val cached = servers.queryByHostNameAndPort("example.com", 443)
    assertEquals(found.getId(), cached!!.getId())
  }

  @Test
  fun queryByHostNameAndPort_doesNotConfuseHostWithPortSuffix() {
    // Without delimiter, "host1" + "23" collides with "host12" + "3"
    servers.create(Server("host1", 23, "HTTP"))
    servers.create(Server("host12", 3, "HTTP"))

    val a = requireNotNull(servers.queryByHostNameAndPort("host1", 23))
    val b = requireNotNull(servers.queryByHostNameAndPort("host12", 3))
    assertEquals(23, a.getPort())
    assertEquals(3, b.getPort())
  }
}
