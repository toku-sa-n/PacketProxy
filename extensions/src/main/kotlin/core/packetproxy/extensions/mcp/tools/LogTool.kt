package packetproxy.extensions.mcp.tools

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.Date
import java.util.regex.Pattern
import packetproxy.model.Configs
import packetproxy.util.LogLineStyle
import packetproxy.util.getStructuredLogEntries
import packetproxy.util.log

class LogTool(configs: Configs) : AuthenticatedMCPTool(configs) {

  private val dateFormat = DateTimeFormatter.ISO_OFFSET_DATE_TIME
  private val dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss")

  override fun getName(): String = "get_logs"

  override fun getDescription(): String = "Get logs from PacketProxy"

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var levelProp = JsonObject()
    levelProp.addProperty("type", "string")
    levelProp.addProperty("description", "Log level filter: debug, info, warn, error")
    levelProp.addProperty("default", "info")
    schema.add("level", levelProp)

    var limitProp = JsonObject()
    limitProp.addProperty("type", "integer")
    limitProp.addProperty("description", "Maximum number of log entries to return")
    limitProp.addProperty("default", 100)
    schema.add("limit", limitProp)

    var sinceProp = JsonObject()
    sinceProp.addProperty("type", "string")
    sinceProp.addProperty(
      "description",
      "Start time in ISO 8601 format (e.g., 2025-01-15T00:00:00Z)",
    )
    schema.add("since", sinceProp)

    var filterProp = JsonObject()
    filterProp.addProperty("type", "string")
    filterProp.addProperty("description", "Regular expression filter for log messages")
    schema.add("filter", filterProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("LogTool called with arguments: " + getSafeArgumentsString(arguments))

    var level = if (arguments.has("level")) arguments.get("level").getAsString() else "info"
    var limit = if (arguments.has("limit")) arguments.get("limit").getAsInt() else 100
    var since = if (arguments.has("since")) arguments.get("since").getAsString() else null
    var filter = if (arguments.has("filter")) arguments.get("filter").getAsString() else null

    if (limit < 1 || limit > 1000) {
      throw Exception("Limit must be between 1 and 1000")
    }

    if (!isValidLogLevel(level)) {
      throw Exception("Invalid log level. Use: debug, info, warn, error")
    }

    var sinceDateTime: OffsetDateTime? = null
    if (since != null) {
      try {
        sinceDateTime = OffsetDateTime.parse(since, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
      } catch (_: DateTimeParseException) {
        try {
          sinceDateTime =
            LocalDateTime.parse(
                since.removeSuffix("Z"),
                DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"),
              )
              .atZone(ZoneId.systemDefault())
              .toOffsetDateTime()
        } catch (e: DateTimeParseException) {
          throw Exception("Invalid date format. Use ISO 8601 format (e.g., 2025-01-15T00:00:00Z)")
        }
      }
    }

    var filterPattern: Pattern? = null
    if (filter != null && !filter.trim().isEmpty()) {
      try {
        filterPattern = Pattern.compile(filter, Pattern.CASE_INSENSITIVE)
      } catch (e: Exception) {
        throw Exception("Invalid regex pattern: " + e.message)
      }
    }

    try {
      var logEntries = getLogEntriesFromGUILog(level, sinceDateTime, filterPattern, limit)

      var logsArray = JsonArray()
      for (entry in logEntries) {
        var logJson = JsonObject()
        logJson.addProperty(
          "timestamp",
          OffsetDateTime.ofInstant(entry.getTimestamp().toInstant(), ZoneId.systemDefault())
            .format(dateFormat),
        )
        logJson.addProperty("level", entry.getLevel())
        logJson.addProperty("message", entry.getMessage())
        logJson.addProperty("thread", entry.getThread())
        logJson.addProperty("class", entry.getClassName())
        logsArray.add(logJson)
      }

      var data = JsonObject()
      data.add("logs", logsArray)
      data.addProperty("total_count", logEntries.size)
      data.addProperty("has_more", logEntries.size >= limit)

      log("LogTool returning " + logsArray.size() + " log entries")
      return data
    } catch (e: Exception) {
      log("LogTool error: " + e.message)
      throw Exception("Failed to get logs: " + e.message)
    }
  }

  private fun isValidLogLevel(level: String): Boolean =
    level == "debug" || level == "info" || level == "warn" || level == "error"

  private fun getLogEntriesFromGUILog(
    level: String,
    since: OffsetDateTime?,
    filter: Pattern?,
    limit: Int,
  ): List<LogEntry> {
    var entries = ArrayList<LogEntry>()

    try {
      var structured = getStructuredLogEntries()
      if (structured.isNotEmpty()) {
        for (item in structured) {
          var entry = parseStructuredEntry(item.rawLine, item.level) ?: continue
          entries.add(entry)
        }
      }
      entries.reverse()
    } catch (e: Exception) {
      log("Error getting log entries: " + e.message)
    }

    var filteredEntries = ArrayList<LogEntry>()
    for (entry in entries) {
      if (!matchesLogLevel(entry.getLevel(), level)) {
        continue
      }

      if (since != null) {
        var entryTime =
          OffsetDateTime.ofInstant(entry.getTimestamp().toInstant(), ZoneId.systemDefault())
        if (entryTime.isBefore(since)) {
          continue
        }
      }

      if (filter != null && !filter.matcher(entry.getMessage()).find()) {
        continue
      }

      filteredEntries.add(entry)
      if (filteredEntries.size >= limit) {
        break
      }
    }

    return filteredEntries
  }

  private fun matchesLogLevel(entryLevel: String, filterLevel: String): Boolean {
    var entryPriority = getLogLevelPriority(entryLevel)
    var filterPriority = getLogLevelPriority(filterLevel)
    return entryPriority >= filterPriority
  }

  private fun getLogLevelPriority(level: String): Int =
    when (level.lowercase()) {
      "debug" -> 0
      "info" -> 1
      "warn" -> 2
      "error" -> 3
      else -> 1
    }

  private fun parseStructuredEntry(line: String, structuredLevel: String): LogEntry? {
    try {
      if (line.length < 19) {
        return null
      }

      var (timestampPart, messagePart) = LogLineStyle.splitLogLine(line.trim())
      var timestamp: Date
      try {
        var dateTimePart = timestampPart.trim().take(19)
        var localDateTime = LocalDateTime.parse(dateTimePart, dtf)
        timestamp = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant())
      } catch (_: DateTimeParseException) {
        timestamp = Date()
      }

      // Prefer structured level from LogSink; do not infer from message substrings.
      return LogEntry(timestamp, structuredLevel, messagePart, "main", "packetproxy")
    } catch (_: Exception) {
      return null
    }
  }

  private class LogEntry(
    private val timestamp: Date,
    private val level: String,
    private val message: String,
    private val thread: String,
    private val className: String,
  ) {
    fun getTimestamp(): Date = timestamp

    fun getLevel(): String = level

    fun getMessage(): String = message

    fun getThread(): String = thread

    fun getClassName(): String = className
  }
}
