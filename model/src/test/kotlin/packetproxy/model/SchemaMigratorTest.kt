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
  fun backupCurrent_copiesDatabaseAndKeepsOnlyFiveNewest() {
    val dir = Files.createTempDirectory("schema_migrator_backup")
    val tempDb = dir.resolve("resources.sqlite3")
    val isolated = Database()
    isolated.openAt(tempDb.toString())
    val dao = isolated.createTable(Filter::class.java)
    dao.create(Filter("a", "b"))

    repeat(6) { index ->
      // Distinct mtimes so rotation order is stable across filesystems.
      Thread.sleep(15)
      isolated.backupCurrent()
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
