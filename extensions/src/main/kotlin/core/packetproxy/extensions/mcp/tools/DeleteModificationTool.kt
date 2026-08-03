package packetproxy.extensions.mcp.tools

import com.google.gson.JsonObject
import packetproxy.model.Configs
import packetproxy.model.Modifications
import packetproxy.util.log

/**
 * Deletes a persistent Auto Modifications rule (Options → Auto Modifications). Not a one-off
 * modification for resend_packet / bulk_send.
 */
class DeleteModificationTool(private val modifications: Modifications, configs: Configs) :
  AuthenticatedMCPTool(configs) {

  override fun getName(): String = "delete_modification"

  override fun getDescription(): String =
    "Delete an Auto Modifications rule (persistent auto-tamper) by id."

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var idProp = JsonObject()
    idProp.addProperty("type", "integer")
    idProp.addProperty("description", "Modification rule id to delete")
    schema.add("id", idProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("DeleteModificationTool called with arguments: " + getSafeArgumentsString(arguments))

    if (!arguments.has("id")) {
      throw IllegalArgumentException("id parameter is required")
    }

    var id = arguments.get("id").asInt
    var existing =
      modifications.query(id) ?: throw IllegalArgumentException("Modification not found: id=$id")

    modifications.delete(existing)

    var result = JsonObject()
    result.addProperty("success", true)
    result.addProperty("deleted_id", id)
    result.addProperty("message", "Modification deleted: id=$id")

    log("DeleteModificationTool deleted modification id=$id")
    return result
  }
}
