package packetproxy.extensions.mcp.tools

import com.google.gson.Gson
import com.google.gson.JsonObject
import java.io.File
import java.io.FileReader
import java.io.IOException
import packetproxy.common.ConfigIO
import packetproxy.model.Configs
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class RestoreConfigTool(private val configIO: ConfigIO, configs: Configs) :
  AuthenticatedMCPTool(configs) {

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
      var backupConfig = loadBackupConfig(backupId)

      var updateArgs = JsonObject()
      updateArgs.add("config_json", backupConfig)
      updateArgs.addProperty("backup", true)
      updateArgs.addProperty("suppress_dialog", suppressDialog)
      updateArgs.addProperty("access_token", arguments.get("access_token").getAsString())

      UpdateConfigTool(configIO, configs).call(updateArgs)

      var data = JsonObject()
      data.addProperty("success", true)
      data.addProperty("backup_id_restored", backupId)
      data.addProperty("config_restored", true)

      log("RestoreConfigTool: Configuration restore completed successfully")
      return data
    } catch (e: Exception) {
      log("RestoreConfigTool error: " + e.message)
      errWithStackTrace(e)
      throw Exception("Failed to restore configuration: " + e.message)
    }
  }

  @Throws(Exception::class)
  private fun loadBackupConfig(backupId: String): JsonObject {
    var backupDir = File(System.getProperty("user.home"), ".packetproxy/backups")
    if (!backupDir.exists()) {
      throw Exception("Backup directory does not exist")
    }

    if (backupId.contains("..") || backupId.contains("/") || backupId.contains("\\")) {
      throw Exception("Invalid backup_id")
    }

    var backupFile = File(backupDir, "$backupId.json")
    var normalizedBackup = backupFile.toPath().normalize()
    var normalizedDir = backupDir.toPath().normalize()
    if (!normalizedBackup.startsWith(normalizedDir)) {
      throw Exception("Invalid backup_id path")
    }

    if (!backupFile.exists()) {
      throw Exception("Backup file not found: $backupId.json")
    }

    log("Loading backup from: " + backupFile.getAbsolutePath())

    try {
      FileReader(backupFile).use { reader ->
        var backupConfig = gson.fromJson(reader, JsonObject::class.java)
        if (backupConfig == null) {
          throw Exception("Invalid backup file format")
        }
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
