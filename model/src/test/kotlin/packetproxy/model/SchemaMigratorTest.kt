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
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class SchemaMigratorTest {
  private lateinit var database: Database

  @BeforeEach
  fun setUp() {
    val tempDb = Files.createTempFile("schema_migrator_test", ".sqlite3")
    database = Database()
    database.openAt(tempDb.toString())
  }

  @Test
  fun ensureColumns_addsMissingColumnAndKeepsExistingRows() {
    val dao = database.createTable(Filter::class.java)
    dao.executeRaw("DROP TABLE `filters`")
    dao.executeRaw(
      "CREATE TABLE `filters` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `name` VARCHAR )"
    )
    dao.executeRaw("INSERT INTO `filters` (`name`) VALUES ('kept')")

    val added = SchemaMigrator.ensureColumns(dao)

    assertTrue(added.contains("filter"))
    assertTrue(SchemaMigrator.hasAllExpectedColumns(dao))
    val names = dao.queryRaw("SELECT name FROM filters").results.map { it[0] }
    assertEquals(listOf("kept"), names)
  }

  @Test
  fun ensureColumns_softAddsModificationPathColumn() {
    val dao = database.createTable(Modification::class.java)
    dao.executeRaw("DROP TABLE `modifications`")
    dao.executeRaw(
      """
      CREATE TABLE `modifications` (
        `id` INTEGER PRIMARY KEY AUTOINCREMENT,
        `enabled` BOOLEAN,
        `server_id` INTEGER,
        `direction` VARCHAR,
        `pattern` VARCHAR,
        `method` VARCHAR,
        `replaced` VARCHAR,
        UNIQUE (`server_id`,`direction`,`pattern`,`method`)
      )
      """
        .trimIndent()
    )
    dao.executeRaw(
      "INSERT INTO `modifications` (`enabled`,`server_id`,`direction`,`pattern`,`method`,`replaced`) VALUES (1, -1, 'CLIENT_REQUEST', 'a', 'SIMPLE', 'b')"
    )

    val added = SchemaMigrator.ensureColumns(dao)

    assertTrue(added.contains("path"))
    assertTrue(SchemaMigrator.hasAllExpectedColumns(dao))
    val path =
      dao.queryRaw("SELECT path FROM modifications").results.map { it[0] }.singleOrNull() ?: ""
    assertEquals("", path)
  }

  @Test
  fun backupCurrent_copiesDatabaseAndKeepsOnlyFiveNewest() {
    val dir = Files.createTempDirectory("schema_migrator_backup")
    val tempDb = dir.resolve("resources.sqlite3")
    val isolated = Database()
    isolated.openAt(tempDb.toString())
    val dao = isolated.createTable(Filter::class.java)
    dao.create(Filter("a", "b"))

    repeat(6) { index ->
      isolated.backupCurrent()
      val backupsDir = tempDb.parent.resolve("backups")
      val newest =
        Files.list(backupsDir).use { stream ->
          stream
            .filter { it.fileName.toString().startsWith("resources-") }
            .filter { it.fileName.toString().endsWith(".sqlite3") }
            .max { a, b -> Files.getLastModifiedTime(a).compareTo(Files.getLastModifiedTime(b)) }
            .orElseThrow()
        }
      // Distinct mtimes so rotation order is stable across filesystems.
      Files.setLastModifiedTime(
        newest,
        java.nio.file.attribute.FileTime.fromMillis(1_700_000_000_000L + index * 1_000L),
      )
      dao.create(Filter("n$index", "f$index"))
    }

    val backupsDir = tempDb.parent.resolve("backups")
    val backups =
      Files.list(backupsDir).use { stream ->
        stream
          .filter { it.fileName.toString().startsWith("resources-") }
          .filter { it.fileName.toString().endsWith(".sqlite3") }
          .toList()
      }
    assertEquals(5, backups.size)
    assertTrue(Files.size(backups.maxBy { Files.getLastModifiedTime(it).toMillis() }) > 0)
  }
}
