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

class ExtensionsPresetSeedTest {
  private lateinit var database: Database
  private lateinit var extensions: Extensions

  @BeforeEach
  fun setUp() {
    Extensions.registerPreset(DummyPresetExtension::class.java)
    val tempDb = Files.createTempFile("extensions_preset_seed", ".sqlite3")
    database = Database()
    database.openAt(tempDb.toString())
    extensions = Extensions(database)
  }

  @Test
  fun init_seedsRegisteredPresets() {
    val names = extensions.queryAll().map { it.getName() }
    assertTrue(names.contains(DummyPresetExtension.NAME))
  }

  @Test
  fun reconnect_reseedsPresetsIntoEmptyProjectDb() {
    val emptyProject = Files.createTempFile("extensions_empty_project", ".sqlite3")
    database.openAt(emptyProject.toString())

    val names = extensions.queryAll().map { it.getName() }
    assertTrue(names.contains(DummyPresetExtension.NAME))
  }

  @Test
  fun ensurePresets_doesNotDuplicateExistingRows() {
    val firstCount = extensions.queryAll().count { it.getName() == DummyPresetExtension.NAME }
    assertEquals(1, firstCount)

    val anotherProject = Files.createTempFile("extensions_preset_again", ".sqlite3")
    database.openAt(anotherProject.toString())
    // Seed into empty DB, then reconnect to same path to re-run ensurePresets.
    database.openAt(anotherProject.toString())

    val secondCount = extensions.queryAll().count { it.getName() == DummyPresetExtension.NAME }
    assertEquals(1, secondCount)
  }

  @Test
  fun queryAll_insertsPresetRegisteredAfterConstruction() {
    Extensions.registerPreset(LateRegisteredPresetExtension::class.java)
    // Clear cache by reconnecting so queryAll runs ensurePresets again.
    database.openAt(database.getDatabasePath().toString())

    val names = extensions.queryAll().map { it.getName() }
    assertTrue(names.contains(LateRegisteredPresetExtension.NAME))
  }

  class DummyPresetExtension : Extension() {
    init {
      setName(NAME)
    }

    companion object {
      const val NAME = "TestPresetExtension"
    }
  }

  class LateRegisteredPresetExtension : Extension() {
    init {
      setName(NAME)
    }

    companion object {
      const val NAME = "LateRegisteredPresetExtension"
    }
  }
}
