package packetproxy.common

import org.apache.commons.io.FilenameUtils
import packetproxy.model.Database

object ProjectDisplayName {
  private const val UNKNOWN = "Unknown"
  private const val DEFAULT = "Default"
  private const val TEMPORARY = "Temporary"

  @JvmStatic
  fun get(): String {
    return try {
      val dbPath = Database.getInstance().getDatabasePath() ?: return UNKNOWN
      fromFileName(dbPath.fileName.toString())
    } catch (_: Exception) {
      UNKNOWN
    }
  }

  @JvmStatic
  fun fromFileName(fileName: String): String =
    when {
      fileName == "resources.sqlite3" -> DEFAULT
      fileName == "resources_temp.sqlite3" -> TEMPORARY
      fileName.startsWith("packetproxy-") &&
        fileName.matches(Regex("packetproxy-\\d{8}-\\d{6}\\.sqlite3")) -> TEMPORARY
      else -> FilenameUtils.removeExtension(fileName)
    }
}
