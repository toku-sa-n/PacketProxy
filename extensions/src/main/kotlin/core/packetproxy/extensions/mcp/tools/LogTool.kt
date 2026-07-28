package packetproxy.extensions.mcp.tools

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.text.SimpleDateFormat
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.Date
import java.util.regex.Pattern
import packetproxy.model.Configs
import packetproxy.util.getLogText
import packetproxy.util.log

class LogTool(configs: Configs) : AuthenticatedMCPTool(configs) {

  private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
  private val dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss")
  private val gson = Gson()

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

    // Validate parameters
    if (limit < 1 || limit > 1000) {
      throw Exception("Limit must be between 1 and 1000")
    }

    if (!isValidLogLevel(level)) {
      throw Exception("Invalid log level. Use: debug, info, warn, error")
    }

    var sinceDateTime: LocalDateTime? = null
    if (since != null) {
      try {
        sinceDateTime =
          LocalDateTime.parse(
            since.replace("Z", ""),
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"),
          )
      } catch (e: DateTimeParseException) {
        throw Exception("Invalid date format. Use ISO 8601 format (e.g., 2025-01-15T00:00:00Z)")
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
      // 実際のログ取得処理
      // PacketProxyのログはutil.Loggingを通してGUILogに保存されているため、
      // そこからログエントリを取得する
      var logEntries = getLogEntriesFromGUILog(level, sinceDateTime, filterPattern, limit)

      var logsArray = JsonArray()
      for (entry in logEntries) {
        var logJson = JsonObject()
        logJson.addProperty("timestamp", dateFormat.format(entry.getTimestamp()))
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

      var content = JsonObject()
      content.addProperty("type", "text")
      content.addProperty("text", gson.toJson(data))

      var contentArray = JsonArray()
      contentArray.add(content)

      var result = JsonObject()
      result.add("content", contentArray)

      log("LogTool returning " + logsArray.size() + " log entries")
      return result
    } catch (e: Exception) {
      log("LogTool error: " + e.message)
      throw Exception("Failed to get logs: " + e.message)
    }
  }

  private fun isValidLogLevel(level: String): Boolean =
    level == "debug" || level == "info" || level == "warn" || level == "error"

  private fun getLogEntriesFromGUILog(
    level: String,
    since: LocalDateTime?,
    filter: Pattern?,
    limit: Int,
  ): List<LogEntry> {
    var entries = ArrayList<LogEntry>()

    try {
      var logText = getLogText()

      if (logText != null && !logText.trim().isEmpty()) {
        // ログテキストを行ごとに分析
        var lines = logText.split("\n")

        for (line in lines) {
          if (line.trim().isEmpty()) {
            continue
          }

          var entry = parseLogLine(line.trim())
          if (entry != null) {
            entries.add(entry)
          }
        }
      }

      // 最新のログが上に来るようにリバース
      entries.reverse()
    } catch (e: Exception) {
      log("Error getting log entries: " + e.message)
    }

    // フィルタリング適用
    var filteredEntries = ArrayList<LogEntry>()
    for (entry in entries) {
      // レベルフィルタ
      if (!matchesLogLevel(entry.getLevel(), level)) {
        continue
      }

      // 時間フィルタ
      if (since != null) {
        var entryTime =
          LocalDateTime.ofInstant(entry.getTimestamp().toInstant(), ZoneId.systemDefault())
        if (entryTime.isBefore(since)) {
          continue
        }
      }

      // 正規表現フィルタ
      if (filter != null && !filter.matcher(entry.getMessage()).find()) {
        continue
      }

      filteredEntries.add(entry)

      // 制限チェック
      if (filteredEntries.size >= limit) {
        break
      }
    }

    return filteredEntries
  }

  private fun matchesLogLevel(entryLevel: String, filterLevel: String): Boolean {
    // レベルの優先度: debug < info < warn < error
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
      else -> 1 // デフォルトはinfo
    }

  private fun parseLogLine(line: String): LogEntry? {
    try {
      // PacketProxyのログ形式: "yyyy/MM/dd HH:mm:ss message"
      // util.Loggingの形式に基づく
      if (line.length < 19) {
        return null // 最小の日時フォーマット長より短い
      }

      var dateTimePart = line.substring(0, 19)
      var messagePart = if (line.length > 26) line.substring(26) else ""

      // 日時をパース
      var timestamp: Date
      try {
        var localDateTime = LocalDateTime.parse(dateTimePart, dtf)
        timestamp = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant())
      } catch (e: DateTimeParseException) {
        // 日時パースに失敗した場合は現在時刻を使用
        timestamp = Date()
      }

      // ログレベルを推定（メッセージ内容から）
      var level = "info" // デフォルト
      var lowerMessage = messagePart.lowercase()
      if (
        lowerMessage.contains("error") ||
          lowerMessage.contains("exception") ||
          lowerMessage.contains("failed") ||
          lowerMessage.contains("fail")
      ) {
        level = "error"
      } else if (lowerMessage.contains("warn") || lowerMessage.contains("warning")) {
        level = "warn"
      } else if (lowerMessage.contains("debug")) {
        level = "debug"
      }

      // スレッド名とクラス名を推定
      var thread = "main" // デフォルト
      var className = "packetproxy" // デフォルト

      // メッセージからクラス名を抽出を試行
      if (messagePart.contains("MCP")) {
        className = "packetproxy.extensions.mcp"
      } else if (messagePart.contains("Server")) {
        className = "packetproxy.extensions.mcp.MCPServer"
      } else if (messagePart.contains("Tool")) {
        className = "packetproxy.extensions.mcp.tools"
      }

      return LogEntry(timestamp, level, messagePart, thread, className)
    } catch (e: Exception) {
      // パースに失敗した場合はnullを返す
      return null
    }
  }

  // ログエントリを表すクラス
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
