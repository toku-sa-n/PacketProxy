package packetproxy.extensions.mcp.tools

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.io.BufferedReader
import java.io.File
import java.io.FileWriter
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import packetproxy.model.Configs
import packetproxy.util.log

class UpdateConfigTool(configs: Configs) : AuthenticatedMCPTool(configs) {

  private val gson = Gson()
  private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")

  override fun getName(): String = "update_config"

  override fun getDescription(): String =
    "Update PacketProxy configuration settings with complete configuration object. IMPORTANT: Requires a complete configuration object, not partial updates."

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var configJsonProp = JsonObject()
    configJsonProp.addProperty("type", "object")
    configJsonProp.addProperty(
      "description",
      "PacketProxyHub-compatible configuration JSON containing COMPLETE configuration object. Must include all required arrays: listenPorts, servers, modifications, sslPassThroughs (can be empty arrays). Partial configurations will cause null pointer errors. Recommended workflow: 1) Call get_config() first, 2) Modify specific fields in the returned object, 3) Pass the entire modified object here.",
    )
    schema.add("config_json", configJsonProp)

    var backupProp = JsonObject()
    backupProp.addProperty("type", "boolean")
    backupProp.addProperty("description", "Create backup of existing configuration (default: true)")
    backupProp.addProperty("default", true)
    schema.add("backup", backupProp)

    var suppressDialogProp = JsonObject()
    suppressDialogProp.addProperty("type", "boolean")
    suppressDialogProp.addProperty(
      "description",
      "Suppress confirmation dialog for configuration update (default: false)",
    )
    suppressDialogProp.addProperty("default", false)
    schema.add("suppress_dialog", suppressDialogProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("UpdateConfigTool called with arguments: " + getSafeArgumentsString(arguments))

    if (!arguments.has("config_json")) {
      throw Exception("config_json parameter is required")
    }

    var configJson = arguments.getAsJsonObject("config_json")
    var backup = if (arguments.has("backup")) arguments.get("backup").getAsBoolean() else true
    var suppressDialog =
      if (arguments.has("suppress_dialog")) arguments.get("suppress_dialog").getAsBoolean()
      else false

    try {
      log("UpdateConfigTool step 1: Starting configuration update")

      var backupInfo: JsonObject? = null

      if (backup) {
        log("UpdateConfigTool step 2: Creating backup")
        backupInfo = createConfigBackup()
        log("UpdateConfigTool step 3: Backup created successfully")
      }

      log("UpdateConfigTool step 4: Updating configuration")
      updateConfiguration(configJson, suppressDialog)
      log("UpdateConfigTool step 5: Configuration updated successfully")

      log("UpdateConfigTool step 6: Building response data")
      var data = JsonObject()
      data.addProperty("success", true)
      data.addProperty("backup_created", backup)
      if (backupInfo != null) {
        data.add("backup_info", backupInfo)
      }
      data.addProperty("config_updated", true)

      var jsonText = data.toString()
      log("UpdateConfigTool step 7: Response data JSON: $jsonText")

      var content = JsonObject()
      content.addProperty("type", "text")
      content.addProperty("text", jsonText)

      var contentArray = JsonArray()
      contentArray.add(content)

      var result = JsonObject()
      result.add("content", contentArray)

      var resultJson = result.toString()
      log("UpdateConfigTool step 8: Final result JSON length: " + resultJson.length)
      log("UpdateConfigTool step 9: Configuration update completed successfully")
      return result
    } catch (e: Exception) {
      log("UpdateConfigTool error: " + e.message)
      e.printStackTrace()
      throw Exception("Failed to update configuration: " + e.message)
    }
  }

  @Throws(Exception::class)
  private fun createConfigBackup(): JsonObject {
    var now = Date()
    var timestamp = dateFormat.format(now)
    var backupId =
      "backup_" + timestamp.replace(":", "").replace("-", "").replace("T", "_").replace("Z", "")

    // Create backup directory if it doesn't exist
    var backupDir = File("backup")
    if (!backupDir.exists()) {
      backupDir.mkdirs()
    }

    var backupPath = backupDir.getPath() + File.separator + backupId + ".json"

    try {
      // HTTP APIで設定を直接取得（認証チェックを回避）
      var configText = getConfigFromHttpApiForBackup()
      var backupConfig = gson.fromJson(configText, JsonObject::class.java)

      // Write backup to file
      FileWriter(backupPath).use { writer ->
        gson.toJson(backupConfig, writer)
        writer.flush()
      }

      log("Configuration backed up to: $backupPath")
      log("Backup content size: " + configText.length + " characters")
    } catch (e: IOException) {
      log("Failed to write backup file: " + e.message)
      throw Exception("Failed to create backup file: " + e.message)
    } catch (e: Exception) {
      log("Failed to create backup: " + e.message)
      throw Exception("Failed to create configuration backup: " + e.message)
    }

    var backupInfo = JsonObject()
    backupInfo.addProperty("backup_id", backupId)
    backupInfo.addProperty("backup_path", backupPath)
    backupInfo.addProperty("timestamp", timestamp)

    log("Created configuration backup: $backupId")
    log("Backup info JSON: " + backupInfo.toString())
    return backupInfo
  }

  @Throws(Exception::class)
  private fun updateConfiguration(configJson: JsonObject, suppressDialog: Boolean) {
    log("UpdateConfigTool starting configuration update using HTTP API")

    // HTTP POST APIで設定を更新（削除処理も自動実行）
    updateConfigViaHttpApi(configJson.toString(), suppressDialog)

    log("UpdateConfigTool configuration update completed using HTTP API")
  }

  @Throws(Exception::class)
  private fun updateConfigViaHttpApi(configJsonString: String, suppressDialog: Boolean) {
    // 設定済みAccessTokenを取得（HTTPリクエスト用）
    var accessToken = getConfiguredAccessToken()

    // HTTP POSTリクエスト
    var url = URL("http://localhost:32349/config")
    var conn = url.openConnection() as HttpURLConnection
    conn.setRequestMethod("POST")
    conn.setRequestProperty("Authorization", accessToken)
    conn.setRequestProperty("Content-Type", "application/json")
    if (suppressDialog) {
      conn.setRequestProperty("X-Suppress-Dialog", "true")
    }
    conn.setDoOutput(true)
    conn.setConnectTimeout(5000)
    conn.setReadTimeout(60000)

    // リクエストボディを送信
    conn.getOutputStream().use { os: OutputStream ->
      var input = configJsonString.toByteArray(Charsets.UTF_8)
      os.write(input, 0, input.size)
    }

    var responseCode = conn.getResponseCode()
    if (responseCode != 200) {
      // エラーレスポンスがある場合は読み取り
      var errorMessage = "HTTP API returned status: $responseCode"
      if (conn.getErrorStream() != null) {
        BufferedReader(InputStreamReader(conn.getErrorStream())).use { reader ->
          var error = StringBuilder()
          var line: String?
          while (reader.readLine().also { line = it } != null) {
            error.append(line)
          }
          if (error.length > 0) {
            errorMessage += ". Error: " + error.toString()
          }
        }
      }
      throw Exception(
        "$errorMessage. Check if config sharing is enabled and user confirmed the operation."
      )
    }

    // 成功レスポンスを読み取り（必要に応じて）
    BufferedReader(InputStreamReader(conn.getInputStream())).use { reader ->
      var response = StringBuilder()
      var line: String?
      while (reader.readLine().also { line = it } != null) {
        response.append(line)
      }
      log("HTTP API response: " + response.toString())
    }

    conn.disconnect()
  }

  @Throws(Exception::class)
  private fun getConfigFromHttpApiForBackup(): String {
    // 設定済みAccessTokenを取得（HTTPリクエスト用）
    var accessToken = getConfiguredAccessToken()

    // HTTP GETリクエスト
    var url = URL("http://localhost:32349/config")
    var conn = url.openConnection() as HttpURLConnection
    conn.setRequestMethod("GET")
    conn.setRequestProperty("Authorization", accessToken)
    conn.setConnectTimeout(5000)
    conn.setReadTimeout(60000)

    var responseCode = conn.getResponseCode()
    if (responseCode != 200) {
      throw Exception(
        "HTTP API returned status: $responseCode. Check if config sharing is enabled."
      )
    }

    // レスポンスを読み取り
    var reader = BufferedReader(InputStreamReader(conn.getInputStream()))
    var response = StringBuilder()
    var line: String?
    while (reader.readLine().also { line = it } != null) {
      response.append(line)
    }
    reader.close()
    conn.disconnect()

    return response.toString()
  }
}
