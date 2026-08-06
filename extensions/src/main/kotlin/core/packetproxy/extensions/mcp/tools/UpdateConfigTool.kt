package packetproxy.extensions.mcp.tools

import com.google.gson.Gson
import com.google.gson.JsonObject
import java.io.File
import java.io.FileWriter
import java.io.IOException
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.JOptionPane
import javax.swing.SwingUtilities
import packetproxy.common.ConfigIO
import packetproxy.model.Configs
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class UpdateConfigTool(private val configIO: ConfigIO, configs: Configs) :
  AuthenticatedMCPTool(configs) {

  private val gson = Gson()
  private val dateFormat = DateTimeFormatter.ISO_OFFSET_DATE_TIME

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
      var backupInfo: JsonObject? = null

      if (backup) {
        backupInfo = createConfigBackup()
      }

      if (!suppressDialog && !confirmOverwrite()) {
        throw Exception("Configuration update cancelled by user")
      }

      configIO.setOptions(configJson.toString())

      var data = JsonObject()
      data.addProperty("success", true)
      data.addProperty("backup_created", backup)
      if (backupInfo != null) {
        data.add("backup_info", backupInfo)
      }
      data.addProperty("config_updated", true)

      log("UpdateConfigTool: Configuration update completed successfully")
      return data
    } catch (e: Exception) {
      log("UpdateConfigTool error: " + e.message)
      errWithStackTrace(e)
      throw Exception("Failed to update configuration: " + e.message)
    }
  }

  @Throws(Exception::class)
  private fun createConfigBackup(): JsonObject {
    var now = OffsetDateTime.now(ZoneId.systemDefault())
    var timestamp = dateFormat.format(now)
    var backupId =
      "backup_" + timestamp.replace(":", "").replace("-", "").replace("T", "_").replace("+", "_")

    var backupDir = File(System.getProperty("user.home"), ".packetproxy/backups")
    if (!backupDir.exists()) {
      backupDir.mkdirs()
    }

    var backupPath = File(backupDir, "$backupId.json").path

    try {
      var configText = configIO.getOptions()
      var backupConfig = gson.fromJson(configText, JsonObject::class.java)

      FileWriter(backupPath).use { writer ->
        gson.toJson(backupConfig, writer)
        writer.flush()
      }

      log("Configuration backed up to: $backupPath")
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
    return backupInfo
  }

  private fun confirmOverwrite(): Boolean {
    var confirmed = booleanArrayOf(false)
    try {
      if (SwingUtilities.isEventDispatchThread()) {
        confirmed[0] =
          JOptionPane.showConfirmDialog(
            null,
            "Do you want to overwrite config?",
            "Loading config",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE,
          ) == JOptionPane.YES_OPTION
      } else {
        SwingUtilities.invokeAndWait {
          confirmed[0] =
            JOptionPane.showConfirmDialog(
              null,
              "Do you want to overwrite config?",
              "Loading config",
              JOptionPane.YES_NO_OPTION,
              JOptionPane.WARNING_MESSAGE,
            ) == JOptionPane.YES_OPTION
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
      return false
    }
    return confirmed[0]
  }
}
