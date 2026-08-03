package packetproxy.extensions.mcp.tools

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import packetproxy.model.Configs
import packetproxy.model.Modifications
import packetproxy.model.Servers
import packetproxy.util.log

/**
 * Lists persistent Auto Modifications rules (Options → Auto Modifications). Not the one-off
 * modifications used by resend_packet / bulk_send.
 */
class ListModificationsTool(
  private val modifications: Modifications,
  private val servers: Servers,
  configs: Configs,
) : AuthenticatedMCPTool(configs) {

  override fun getName(): String = "list_modifications"

  override fun getDescription(): String =
    "List all Auto Modifications (persistent auto-tamper rules). " +
      "These are the Rules under Options → Auto Modifications, not one-off resend modifications."

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()
    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("ListModificationsTool called with arguments: " + getSafeArgumentsString(arguments))

    var all = modifications.queryAll()
    var items = JsonArray()
    for (modification in all) {
      items.add(ModificationMcpHelpers.toJson(modification, servers))
    }

    var result = JsonObject()
    result.addProperty("count", items.size())
    result.add("modifications", items)

    log("ListModificationsTool returning " + items.size() + " modifications")
    return result
  }
}
