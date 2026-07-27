package packetproxy.extensions.mcp

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.PrintWriter
import packetproxy.extensions.mcp.tools.ToolRegistry
import packetproxy.util.Logging.log

class MCPServer(private val logger: (LogLevel, String) -> Unit) {

  private val gson: Gson = GsonBuilder().setPrettyPrinting().create()
  private val toolRegistry = ToolRegistry()
  private var running = false
  private var reader: BufferedReader = BufferedReader(InputStreamReader(System.`in`))
  private var writer: PrintWriter = PrintWriter(System.out, true)

  @Throws(IOException::class)
  fun run() {
    running = true
    logInfo("MCP Server listening on stdin/stdout")

    while (running) {
      try {
        var line = reader.readLine()
        if (line == null) {
          break // EOF
        }

        line = line.trim()
        if (line.isEmpty()) {
          continue
        }

        logInfo("Received: $line")
        processRequest(line)
      } catch (e: Exception) {
        logError("Error processing request: " + e.message)
        log("MCP Server error: " + e.message)
        e.printStackTrace()
      }
    }
  }

  fun stop() {
    running = false
    // Don't close System.in/System.out streams as they are global
    // Just mark as stopped - the run() loop will break on next read
  }

  @Throws(Exception::class)
  fun processTestRequest(request: JsonObject): JsonObject {
    var method = request.get("method").getAsString()
    var id = request.get("id")
    var params = if (request.has("params")) request.getAsJsonObject("params") else JsonObject()

    var response = JsonObject()
    response.addProperty("jsonrpc", "2.0")
    // Always ensure ID is present - use original request ID or default
    if (id != null && !id.isJsonNull) {
      response.add("id", id)
    } else {
      // If no valid ID in request, use default ID
      response.addProperty("id", 0)
    }

    try {
      var result = handleMethod(method, params)
      response.add("result", result)
    } catch (e: Exception) {
      var error = JsonObject()
      error.addProperty("code", -32603)
      error.addProperty("message", "Internal error: " + e.message)
      response.add("error", error)
      // Don't throw exception - return error response instead
      logError("Method error: " + e.message)
    }

    return response
  }

  private fun processRequest(requestLine: String) {
    try {
      var request = JsonParser.parseString(requestLine).getAsJsonObject()

      var method = request.get("method").getAsString()
      var id = request.get("id")
      var params = if (request.has("params")) request.getAsJsonObject("params") else JsonObject()

      var response = JsonObject()
      response.addProperty("jsonrpc", "2.0")
      // Always ensure ID is present - use original request ID or default
      if (id != null && !id.isJsonNull) {
        response.add("id", id)
      } else {
        // If no valid ID in request, use default ID
        response.addProperty("id", 0)
      }

      try {
        var result = handleMethod(method, params)
        response.add("result", result)
      } catch (e: Exception) {
        var error = JsonObject()
        error.addProperty("code", -32603)
        error.addProperty("message", "Internal error: " + e.message)
        response.add("error", error)
        logError("Method error: " + e.message)
      }

      var responseString = gson.toJson(response)
      writer.println(responseString)
      logInfo("Sent: $responseString")
    } catch (e: Exception) {
      // Invalid JSON request
      var errorResponse = JsonObject()
      errorResponse.addProperty("jsonrpc", "2.0")

      // Try to extract ID from the malformed request if possible
      var requestId: JsonElement? = null
      try {
        var partialRequest = JsonParser.parseString(requestLine).getAsJsonObject()
        if (partialRequest.has("id")) {
          requestId = partialRequest.get("id")
        }
      } catch (parseError: Exception) {
        // If we can't parse at all, use null ID
      }
      errorResponse.add("id", requestId)

      var error = JsonObject()
      error.addProperty("code", -32700)
      error.addProperty("message", "Parse error")
      errorResponse.add("error", error)

      writer.println(gson.toJson(errorResponse))
      logError("Parse error: " + e.message)
    }
  }

  @Throws(Exception::class)
  private fun handleMethod(method: String, params: JsonObject): JsonObject =
    when (method) {
      "initialize" -> handleInitialize(params)
      "tools/list" -> handleToolsList()
      "tools/call" -> handleToolsCall(params)
      "resources/list" -> handleResourcesList()
      "resources/templates/list" -> handleResourcesTemplatesList()
      "prompts/list" -> handlePromptsList()
      else -> throw Exception("Unknown method: $method")
    }

  private fun handleInitialize(params: JsonObject): JsonObject {
    var result = JsonObject()

    var capabilities = JsonObject()
    var tools = JsonObject()
    tools.addProperty("listChanged", true)
    capabilities.add("tools", tools)

    var serverInfo = JsonObject()
    serverInfo.addProperty("name", "PacketProxy MCP Server")
    serverInfo.addProperty("version", "1.0.0")

    result.add("capabilities", capabilities)
    result.addProperty("protocolVersion", "2024-11-05")
    result.add("serverInfo", serverInfo)

    logInfo("Client initialized")
    return result
  }

  private fun handleToolsList(): JsonObject {
    var result = JsonObject()
    result.add("tools", toolRegistry.getToolsList())
    return result
  }

  @Throws(Exception::class)
  private fun handleToolsCall(params: JsonObject): JsonObject {
    if (!params.has("name")) {
      throw Exception("Tool name is required")
    }

    var toolName = params.get("name").getAsString()
    var arguments =
      if (params.has("arguments")) params.getAsJsonObject("arguments") else JsonObject()

    return toolRegistry.callTool(toolName, arguments)
  }

  private fun handleResourcesList(): JsonObject {
    var result = JsonObject()
    var resources = arrayOf<JsonObject>()
    result.add("resources", gson.toJsonTree(resources))
    return result
  }

  private fun handleResourcesTemplatesList(): JsonObject {
    var result = JsonObject()
    var resourceTemplates = arrayOf<JsonObject>()
    result.add("resourceTemplates", gson.toJsonTree(resourceTemplates))
    return result
  }

  private fun handlePromptsList(): JsonObject {
    var result = JsonObject()
    var prompts = arrayOf<JsonObject>()
    result.add("prompts", gson.toJsonTree(prompts))
    return result
  }

  private fun logInfo(message: String) {
    logger(LogLevel.INFO, message)
  }

  private fun logError(message: String) {
    logger(LogLevel.ERROR, message)
  }
}
