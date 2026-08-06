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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ModificationsQueryCacheTest {
  private lateinit var database: Database
  private lateinit var modifications: Modifications

  @BeforeEach
  fun setUp() {
    val tempDb = Files.createTempFile("modifications_query_cache_test", ".sqlite3")
    database = Database()
    database.openAt(tempDb.toString())
    modifications = Modifications(database)
  }

  @Test
  fun query_byId_usesIdAsCacheKeyNotZero() {
    val a =
      Modification(
        Modification.Direction.CLIENT_REQUEST,
        "foo",
        "bar",
        Modification.Method.SIMPLE,
        null,
      )
    val b =
      Modification(
        Modification.Direction.SERVER_RESPONSE,
        "baz",
        "qux",
        Modification.Method.SIMPLE,
        null,
      )
    modifications.create(a)
    modifications.create(b)

    val loadedA = requireNotNull(modifications.query(a.getId()))
    val loadedB = requireNotNull(modifications.query(b.getId()))

    assertEquals(a.getId(), loadedA.getId())
    assertEquals(b.getId(), loadedB.getId())
    assertEquals("foo", loadedA.getPattern())
    assertEquals("baz", loadedB.getPattern())
  }

  @Test
  fun query_returnsCachedInstanceForSameId() {
    val mod =
      Modification(Modification.Direction.ALL, "pat", "rep", Modification.Method.SIMPLE, null)
    modifications.create(mod)

    val first = requireNotNull(modifications.query(mod.getId()))
    val second = requireNotNull(modifications.query(mod.getId()))
    assertSame(first, second)
  }

  @Test
  fun query_returnsNullForMissingId() {
    assertNull(modifications.query(999_999))
  }
}
