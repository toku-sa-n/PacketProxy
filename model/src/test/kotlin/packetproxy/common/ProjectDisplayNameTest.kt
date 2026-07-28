package packetproxy.common

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ProjectDisplayNameTest {
  @Test
  fun fromFileNameDefaultDatabase() {
    assertEquals("Default", fromFileName("resources.sqlite3"))
  }

  @Test
  fun fromFileNameNamedProject() {
    assertEquals("myproject", fromFileName("myproject.sqlite3"))
  }

  @Test
  fun fromFileNameTemporaryTimestampedProject() {
    assertEquals("Temporary", fromFileName("packetproxy-20260409-193537.sqlite3"))
  }

  @Test
  fun fromFileNameResourcesTemp() {
    assertEquals("Temporary", fromFileName("resources_temp.sqlite3"))
  }
}
