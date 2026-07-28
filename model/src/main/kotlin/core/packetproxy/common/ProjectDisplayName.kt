package packetproxy.common

import org.apache.commons.io.FilenameUtils
import packetproxy.model.Database

private const val UNKNOWN = "Unknown"
private const val DEFAULT = "Default"
private const val TEMPORARY = "Temporary"

fun get(database: Database): String {
  return try {
    val dbPath = database.getDatabasePath()
    fromFileName(dbPath.fileName.toString())
  } catch (_: Exception) {
    UNKNOWN
  }
}

fun fromFileName(fileName: String): String =
  when {
    fileName == "resources.sqlite3" -> DEFAULT
    fileName == "resources_temp.sqlite3" -> TEMPORARY
    fileName.startsWith("packetproxy-") &&
      fileName.matches(Regex("packetproxy-\\d{8}-\\d{6}\\.sqlite3")) -> TEMPORARY
    else -> FilenameUtils.removeExtension(fileName)
  }
