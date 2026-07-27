package packetproxy.common

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import packetproxy.util.Logging.errWithStackTrace

object RecentProjectsStore {
  private const val MAX_RECENTS = 10
  private val recentFile: Path =
    Paths.get(System.getProperty("user.home"), ".packetproxy", "recent_projects")

  @JvmStatic
  fun load(): List<String> {
    return try {
      if (!Files.exists(recentFile)) {
        return emptyList()
      }
      Files.readAllLines(recentFile, StandardCharsets.UTF_8)
        .map(String::trim)
        .filter(String::isNotEmpty)
    } catch (e: Exception) {
      errWithStackTrace(e)
      emptyList()
    }
  }

  @JvmStatic
  fun add(path: Path) {
    try {
      val deduplicated = linkedSetOf(path.toString()).apply { addAll(load()) }
      save(deduplicated.take(MAX_RECENTS))
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @JvmStatic
  @Throws(Exception::class)
  fun save(recents: List<String>) {
    recentFile.parent?.let { Files.createDirectories(it) }
    Files.write(recentFile, recents, StandardCharsets.UTF_8)
  }
}
