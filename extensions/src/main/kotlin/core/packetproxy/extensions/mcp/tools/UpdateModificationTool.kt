package packetproxy.extensions.mcp.tools

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import packetproxy.model.Configs
import packetproxy.model.Modification
import packetproxy.model.Modifications
import packetproxy.model.Servers
import packetproxy.util.log

/**
 * Updates a persistent Auto Modifications rule, including enable/disable. Not a one-off
 * modification for resend_packet / bulk_send.
 */
class UpdateModificationTool(
  private val modifications: Modifications,
  private val servers: Servers,
  configs: Configs,
) : AuthenticatedMCPTool(configs) {

  override fun getName(): String = "update_modification"

  override fun getDescription(): String =
    "Update an Auto Modifications rule (persistent auto-tamper) by id. " +
      "Pass only fields to change. Use enabled=true/false to toggle the rule."

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var idProp = JsonObject()
    idProp.addProperty("type", "integer")
    idProp.addProperty("description", "Modification rule id to update")
    schema.add("id", idProp)

    var patternProp = JsonObject()
    patternProp.addProperty("type", "string")
    patternProp.addProperty("description", "New pattern (optional)")
    schema.add("pattern", patternProp)

    var replacedProp = JsonObject()
    replacedProp.addProperty("type", "string")
    replacedProp.addProperty("description", "New replacement (optional)")
    schema.add("replaced", replacedProp)

    var methodProp = JsonObject()
    methodProp.addProperty("type", "string")
    var methodEnum = JsonArray()
    methodEnum.add("SIMPLE")
    methodEnum.add("REGEX")
    methodEnum.add("BINARY")
    methodProp.add("enum", methodEnum)
    methodProp.addProperty("description", "New method (optional)")
    schema.add("method", methodProp)

    var directionProp = JsonObject()
    directionProp.addProperty("type", "string")
    var directionEnum = JsonArray()
    directionEnum.add("CLIENT_REQUEST")
    directionEnum.add("SERVER_RESPONSE")
    directionEnum.add("ALL")
    directionProp.add("enum", directionEnum)
    directionProp.addProperty("description", "New direction (optional)")
    schema.add("direction", directionProp)

    var serverProp = JsonObject()
    serverProp.addProperty("type", "string")
    serverProp.addProperty(
      "description",
      "New target server display name, or \"*\" for all servers (optional)",
    )
    schema.add("server", serverProp)

    var enabledProp = JsonObject()
    enabledProp.addProperty("type", "boolean")
    enabledProp.addProperty("description", "Enable or disable the rule (optional)")
    schema.add("enabled", enabledProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("UpdateModificationTool called with arguments: " + getSafeArgumentsString(arguments))

    if (!arguments.has("id")) {
      throw IllegalArgumentException("id parameter is required")
    }

    var id = arguments.get("id").asInt
    var modification =
      modifications.query(id) ?: throw IllegalArgumentException("Modification not found: id=$id")

    if (arguments.has("pattern")) {
      modification.setPattern(arguments.get("pattern").asString)
    }
    if (arguments.has("replaced")) {
      modification.setReplaced(arguments.get("replaced").asString)
    }
    if (arguments.has("method")) {
      modification.setMethod(ModificationMcpHelpers.parseMethod(arguments.get("method").asString))
    }
    if (arguments.has("direction")) {
      modification.setDirection(
        ModificationMcpHelpers.parseDirection(arguments.get("direction").asString)
      )
    }
    if (arguments.has("server")) {
      var server = ModificationMcpHelpers.resolveServer(servers, arguments.get("server").asString)
      modification.setServerId(if (server != null) server.getId() else Modification.ALL_SERVER)
    }
    if (arguments.has("enabled")) {
      if (arguments.get("enabled").asBoolean) {
        modification.setEnabled()
      } else {
        modification.setDisabled()
      }
    }

    modifications.update(modification)

    var result = JsonObject()
    result.addProperty("success", true)
    result.add("modification", ModificationMcpHelpers.toJson(modification, servers))

    log("UpdateModificationTool updated modification id=$id")
    return result
  }
}
