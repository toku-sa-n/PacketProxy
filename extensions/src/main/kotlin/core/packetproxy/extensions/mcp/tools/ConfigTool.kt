package packetproxy.extensions.mcp.tools

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import packetproxy.common.ConfigIO
import packetproxy.model.Configs
import packetproxy.util.log

class ConfigTool(private val configIO: ConfigIO, configs: Configs) : AuthenticatedMCPTool(configs) {

  private val gson = Gson()

  override fun getName(): String = "get_config"

  override fun getDescription(): String = "Get PacketProxy configuration settings"

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var categoriesProp = JsonObject()
    categoriesProp.addProperty("type", "array")
    categoriesProp.addProperty(
      "description",
      "Categories to retrieve (empty for all). Available: listenPorts, servers, modifications, sslPassThroughs",
    )

    var itemsProp = JsonObject()
    itemsProp.addProperty("type", "string")
    var enumValues = JsonArray()
    enumValues.add("listenPorts")
    enumValues.add("servers")
    enumValues.add("modifications")
    enumValues.add("sslPassThroughs")
    itemsProp.add("enum", enumValues)
    categoriesProp.add("items", itemsProp)

    schema.add("categories", categoriesProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("ConfigTool called with arguments: " + getSafeArgumentsString(arguments))

    try {
      var allConfig = gson.fromJson(configIO.getOptions(), JsonObject::class.java)
      var filteredConfig = filterByCategories(allConfig, arguments)
      log("ConfigTool returning configuration from ConfigIO")
      return filteredConfig
    } catch (e: Exception) {
      log("ConfigTool error: " + e.message)
      throw Exception("Failed to get configuration: " + e.message)
    }
  }

  private fun filterByCategories(config: JsonObject, arguments: JsonObject): JsonObject {
    if (!arguments.has("categories")) {
      return config
    }

    var categories = arguments.getAsJsonArray("categories")
    if (categories.size() == 0) {
      return config
    }

    var filtered = JsonObject()
    for (i in 0 until categories.size()) {
      var category = categories.get(i).getAsString()
      if (config.has(category)) {
        filtered.add(category, config.get(category))
      }
    }

    return filtered
  }
}
