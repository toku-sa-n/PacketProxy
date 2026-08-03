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
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ModificationPathTest {
  private lateinit var database: Database

  @BeforeEach
  fun setUp() {
    var tempDb = Files.createTempFile("modification_path_test", ".sqlite3")
    database = Database()
    database.openAt(tempDb.toString())
  }

  @Test
  fun matchesPath_returnsTrueWhenPathFilterIsEmpty() {
    var modification = modificationWithPath("")
    assertTrue(modification.matchesPath("/api/v1/users"))
    assertTrue(modification.matchesPath(null))
  }

  @Test
  fun matchesPath_returnsFalseWhenRequestPathIsNullAndFilterIsSet() {
    var modification = modificationWithPath("^/api/")
    assertFalse(modification.matchesPath(null))
  }

  @Test
  fun matchesPath_matchesPrefixRegex() {
    var modification = modificationWithPath("^/api/v1/")
    assertTrue(modification.matchesPath("/api/v1/users"))
    assertFalse(modification.matchesPath("/api/v2/users"))
  }

  @Test
  fun matchesPath_matchesSubstring() {
    var modification = modificationWithPath("/users")
    assertTrue(modification.matchesPath("/api/v1/users"))
    assertFalse(modification.matchesPath("/api/v1/posts"))
  }

  @Test
  fun matchesPath_matchesExact() {
    var modification = modificationWithPath("^/exact$")
    assertTrue(modification.matchesPath("/exact"))
    assertFalse(modification.matchesPath("/exact/more"))
  }

  @Test
  fun matchesPath_returnsFalseForInvalidRegex() {
    var modification = modificationWithPath("[invalid")
    assertFalse(modification.matchesPath("/api"))
  }

  @Test
  fun schema_includesPathInUniqueConstraint() {
    var dao = database.createTable(Modification::class.java)
    var sql =
      dao.queryRaw("SELECT sql FROM sqlite_master WHERE name='modifications'").firstResult[0]
    assertEquals(
      "CREATE TABLE `modifications` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `enabled` BOOLEAN , `server_id` INTEGER , `direction` VARCHAR , `pattern` VARCHAR , `method` VARCHAR , `path` VARCHAR , `replaced` VARCHAR , UNIQUE (`server_id`,`direction`,`pattern`,`method`,`path`) )",
      sql,
    )
  }

  private fun modificationWithPath(path: String): Modification =
    Modification(
      Modification.Direction.CLIENT_REQUEST,
      "pattern",
      "replaced",
      Modification.Method.SIMPLE,
      null,
      path,
    )
}
