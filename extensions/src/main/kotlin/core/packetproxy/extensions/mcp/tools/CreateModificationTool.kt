package packetproxy.extensions.mcp.tools

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import packetproxy.model.Configs
import packetproxy.model.Modification
import packetproxy.model.Modifications
import packetproxy.model.Servers
import packetproxy.util.log

/**
 * Creates a persistent Auto Modifications rule (Options → Auto Modifications). Not a one-off
 * modification for resend_packet / bulk_send.
 */
class CreateModificationTool(
  private val modifications: Modifications,
  private val servers: Servers,
  configs: Configs,
) : AuthenticatedMCPTool(configs) {

  override fun getName(): String = "create_modification"

  override fun getDescription(): String =
    "Create an Auto Modifications rule (persistent auto-tamper). " +
      "Applied automatically to matching traffic. Distinct from resend_packet modifications."

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var patternProp = JsonObject()
    patternProp.addProperty("type", "string")
    patternProp.addProperty(
      "description",
      "Pattern to match. For BINARY, use hex string (e.g. \"48656c6c6f\").",
    )
    schema.add("pattern", patternProp)

    var replacedProp = JsonObject()
    replacedProp.addProperty("type", "string")
    replacedProp.addProperty(
      "description",
      "Replacement text or hex (for BINARY). Applied when pattern matches.",
    )
    schema.add("replaced", replacedProp)

    var methodProp = JsonObject()
    methodProp.addProperty("type", "string")
    var methodEnum = JsonArray()
    methodEnum.add("SIMPLE")
    methodEnum.add("REGEX")
    methodEnum.add("BINARY")
    methodProp.add("enum", methodEnum)
    methodProp.addProperty("description", "Match/replace method")
    schema.add("method", methodProp)

    var directionProp = JsonObject()
    directionProp.addProperty("type", "string")
    var directionEnum = JsonArray()
    directionEnum.add("CLIENT_REQUEST")
    directionEnum.add("SERVER_RESPONSE")
    directionEnum.add("ALL")
    directionProp.add("enum", directionEnum)
    directionProp.addProperty("description", "Traffic direction to apply the rule")
    schema.add("direction", directionProp)

    var serverProp = JsonObject()
    serverProp.addProperty("type", "string")
    serverProp.addProperty(
      "description",
      "Target server display name, or \"*\" for all servers. Default: \"*\"",
    )
    serverProp.addProperty("default", "*")
    schema.add("server", serverProp)

    var enabledProp = JsonObject()
    enabledProp.addProperty("type", "boolean")
    enabledProp.addProperty(
      "description",
      "Whether the rule is enabled after creation. Default: true",
    )
    enabledProp.addProperty("default", true)
    schema.add("enabled", enabledProp)

    var pathProp = JsonObject()
    pathProp.addProperty("type", "string")
    pathProp.addProperty(
      "description",
      "Optional RE2 regex matched against the HTTP request path (no query). " +
        "Empty or omitted applies to all paths. Examples: \"^/api/v1/\", \"/users\", \"^/exact$\". " +
        "Response rules also use the corresponding request path.",
    )
    pathProp.addProperty("default", "")
    schema.add("path", pathProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("CreateModificationTool called with arguments: " + getSafeArgumentsString(arguments))

    if (!arguments.has("pattern")) {
      throw IllegalArgumentException("pattern parameter is required")
    }
    if (!arguments.has("replaced")) {
      throw IllegalArgumentException("replaced parameter is required")
    }
    if (!arguments.has("method")) {
      throw IllegalArgumentException("method parameter is required")
    }
    if (!arguments.has("direction")) {
      throw IllegalArgumentException("direction parameter is required")
    }

    var pattern = arguments.get("pattern").asString
    var replaced = arguments.get("replaced").asString
    var method = ModificationMcpHelpers.parseMethod(arguments.get("method").asString)
    var direction = ModificationMcpHelpers.parseDirection(arguments.get("direction").asString)
    var serverStr = if (arguments.has("server")) arguments.get("server").asString else "*"
    var enabled = if (arguments.has("enabled")) arguments.get("enabled").asBoolean else true
    var path = if (arguments.has("path")) arguments.get("path").asString else ""

    var server = ModificationMcpHelpers.resolveServer(servers, serverStr)
    var modification = Modification(direction, pattern, replaced, method, server, path)
    if (enabled) {
      modification.setEnabled()
    } else {
      modification.setDisabled()
    }

    modifications.create(modification)

    var result = JsonObject()
    result.addProperty("success", true)
    result.add("modification", ModificationMcpHelpers.toJson(modification, servers))

    log("CreateModificationTool created modification id=" + modification.getId())
    return result
  }
}
