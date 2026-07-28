package packetproxy.extensions.mcp.tools

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.io.File
import java.io.FileReader
import java.io.IOException
import packetproxy.model.Configs
import packetproxy.util.log

class RestoreConfigTool(private val configs: Configs) : AuthenticatedMCPTool(configs) {

  private val gson = Gson()

  override fun getName(): String = "restore_config"

  override fun getDescription(): String =
    "Restore PacketProxy configuration from backup file with optional dialog suppression"

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var backupIdProp = JsonObject()
    backupIdProp.addProperty("type", "string")
    backupIdProp.addProperty(
      "description",
      "Backup ID to restore from (e.g., backup_20250103_120000)",
    )
    schema.add("backup_id", backupIdProp)

    var suppressDialogProp = JsonObject()
    suppressDialogProp.addProperty("type", "boolean")
    suppressDialogProp.addProperty(
      "description",
      "Suppress confirmation dialog for configuration restore (default: false)",
    )
    suppressDialogProp.addProperty("default", false)
    schema.add("suppress_dialog", suppressDialogProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("RestoreConfigTool called with arguments: " + getSafeArgumentsString(arguments))

    if (!arguments.has("backup_id")) {
      throw Exception("backup_id parameter is required")
    }

    var backupId = arguments.get("backup_id").getAsString()
    var suppressDialog =
      if (arguments.has("suppress_dialog")) arguments.get("suppress_dialog").getAsBoolean()
      else false

    try {
      log("RestoreConfigTool step 1: Loading backup configuration")
      var backupConfig = loadBackupConfig(backupId)
      log("RestoreConfigTool step 2: Backup configuration loaded successfully")

      log("RestoreConfigTool step 3: Restoring configuration using UpdateConfigTool")
      var updateArgs = JsonObject()
      updateArgs.add("config_json", backupConfig)
      updateArgs.addProperty("backup", true)
      updateArgs.addProperty("suppress_dialog", suppressDialog)
      updateArgs.addProperty("access_token", arguments.get("access_token").getAsString())

      var updateTool = UpdateConfigTool(configs)
      updateTool.call(updateArgs)
      log("RestoreConfigTool step 4: Configuration restored successfully")

      log("RestoreConfigTool step 5: Building response data")
      var data = JsonObject()
      data.addProperty("success", true)
      data.addProperty("backup_id_restored", backupId)
      data.addProperty("config_restored", true)

      var jsonText = data.toString()
      log("RestoreConfigTool step 6: Response data JSON: $jsonText")

      var content = JsonObject()
      content.addProperty("type", "text")
      content.addProperty("text", jsonText)

      var contentArray = JsonArray()
      contentArray.add(content)

      var result = JsonObject()
      result.add("content", contentArray)

      var resultJson = result.toString()
      log("RestoreConfigTool step 7: Final result JSON length: " + resultJson.length)
      log("RestoreConfigTool step 8: Configuration restore completed successfully")
      return result
    } catch (e: Exception) {
      log("RestoreConfigTool error: " + e.message)
      e.printStackTrace()
      throw Exception("Failed to restore configuration: " + e.message)
    }
  }

  @Throws(Exception::class)
  private fun loadBackupConfig(backupId: String): JsonObject {
    // Construct backup file path
    var backupDir = File("backup")
    if (!backupDir.exists()) {
      throw Exception("Backup directory does not exist")
    }

    var backupFileName = "$backupId.json"
    var backupFile = File(backupDir, backupFileName)

    if (!backupFile.exists()) {
      throw Exception("Backup file not found: $backupFileName")
    }

    log("Loading backup from: " + backupFile.getAbsolutePath())

    try {
      FileReader(backupFile).use { reader ->
        var backupConfig = gson.fromJson(reader, JsonObject::class.java)

        if (backupConfig == null) {
          throw Exception("Invalid backup file format")
        }

        log("Backup configuration loaded successfully from: $backupFileName")
        return backupConfig
      }
    } catch (e: IOException) {
      log("Failed to read backup file: " + e.message)
      throw Exception("Failed to read backup file: " + e.message)
    } catch (e: Exception) {
      log("Failed to parse backup file: " + e.message)
      throw Exception("Failed to parse backup file: " + e.message)
    }
  }
}
