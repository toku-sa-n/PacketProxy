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
import org.junit.jupiter.api.Test

class ConfigStringTest {
  @Test
  fun setStringAndGetString_afterDatabaseReconnect() {
    val db1 = Files.createTempFile("config_string_test_1", ".sqlite3")
    val db2 = Files.createTempFile("config_string_test_2", ".sqlite3")
    val database = Database()
    database.openAt(db1.toString())
    val configs = Configs(database)
    val configString = ConfigString(configs, "UIFontName")

    database.openAt(db2.toString())

    configString.setString("SansSerif")
    assertEquals("SansSerif", configString.getString())
  }
}
