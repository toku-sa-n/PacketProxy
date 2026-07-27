package packetproxy.extensions.mcp.tools

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import packetproxy.util.Logging.log

class ConfigTool : AuthenticatedMCPTool() {

  private val gson = Gson()

  override fun getName(): String = "get_config"

  override fun getDescription(): String = "Get PacketProxy configuration settings"

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var categoriesProp = JsonObject()
    categoriesProp.addProperty("type", "array")
    categoriesProp.addProperty("description", "Categories to retrieve (empty for all)")

    var itemsProp = JsonObject()
    itemsProp.addProperty("type", "string")
    var enumValues = JsonArray()
    enumValues.add("listenPorts")
    enumValues.add("servers")
    enumValues.add("modifications")
    enumValues.add("sslPassThroughs")
    enumValues.add("resolutions")
    enumValues.add("interceptOptions")
    enumValues.add("clientCertificates")
    enumValues.add("generalConfigs")
    enumValues.add("extensions")
    enumValues.add("filters")
    enumValues.add("openVPNForwardPorts")
    enumValues.add("charSets")
    itemsProp.add("enum", enumValues)
    categoriesProp.add("items", itemsProp)

    schema.add("categories", categoriesProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("ConfigTool called with arguments: " + getSafeArgumentsString(arguments))

    try {
      // HTTP APIで設定を取得
      var configJson = getConfigFromHttpApi()

      // categoriesでフィルタリングが指定されている場合はフィルタリングを適用
      var allConfig = gson.fromJson(configJson, JsonObject::class.java)
      var filteredConfig = filterByCategories(allConfig, arguments)

      var content = JsonObject()
      content.addProperty("type", "text")
      content.addProperty("text", gson.toJson(filteredConfig))

      var contentArray = JsonArray()
      contentArray.add(content)

      var mcpResult = JsonObject()
      mcpResult.add("content", contentArray)

      log("ConfigTool returning configuration from HTTP API")
      return mcpResult
    } catch (e: Exception) {
      log("ConfigTool error: " + e.message)
      throw Exception("Failed to get configuration: " + e.message)
    }
  }

  @Throws(Exception::class)
  private fun getConfigFromHttpApi(): String {
    // 設定済みAccessTokenを取得（HTTPリクエスト用）
    var accessToken = getConfiguredAccessToken()

    // HTTP GETリクエスト
    var url = URL("http://localhost:32349/config")
    var conn = url.openConnection() as HttpURLConnection
    conn.setRequestMethod("GET")
    conn.setRequestProperty("Authorization", accessToken)
    conn.setConnectTimeout(5000)
    conn.setReadTimeout(10000)

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

  private fun filterByCategories(config: JsonObject, arguments: JsonObject): JsonObject {
    if (!arguments.has("categories")) {
      return config // カテゴリ指定がない場合は全て返す
    }

    var categories = arguments.getAsJsonArray("categories")
    if (categories.size() == 0) {
      return config // 空の場合は全て返す
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
