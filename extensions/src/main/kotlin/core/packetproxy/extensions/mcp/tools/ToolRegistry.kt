package packetproxy.extensions.mcp.tools

import com.google.gson.JsonArray
import com.google.gson.JsonObject

class ToolRegistry {

  private val tools: MutableMap<String, MCPTool>

  init {
    this.tools = HashMap()
    registerDefaultTools()
  }

  private fun registerDefaultTools() {
    // 基本的なツールを登録
    registerTool(HistoryTool())
    registerTool(PacketDetailTool())
    registerTool(LogTool())
    registerTool(ConfigTool())
    registerTool(UpdateConfigTool())
    registerTool(RestoreConfigTool())
    registerTool(ResendPacketTool())
    registerTool(BulkSendTool())
    registerTool(VulCheckHelperTool())
    registerTool(JobStatusTool())
    registerTool(CreateResenderTabHttp2Tool())
  }

  fun registerTool(tool: MCPTool) {
    tools[tool.getName()] = tool
  }

  fun getToolsList(): JsonArray {
    var toolsArray = JsonArray()

    for (tool in tools.values) {
      var toolInfo = JsonObject()
      toolInfo.addProperty("name", tool.getName())
      toolInfo.addProperty("description", tool.getDescription())

      var inputSchema = JsonObject()
      inputSchema.addProperty("type", "object")
      inputSchema.add("properties", tool.getInputSchema())

      toolInfo.add("inputSchema", inputSchema)
      toolsArray.add(toolInfo)
    }

    return toolsArray
  }

  @Throws(Exception::class)
  fun callTool(toolName: String, arguments: JsonObject): JsonObject {
    var tool = tools[toolName]
    if (tool == null) {
      throw Exception("Unknown tool: $toolName")
    }

    var toolResult = tool.call(arguments)

    // MCP仕様に準拠した応答形式に変換
    var mcpResponse = JsonObject()

    // content配列を作成 (必須)
    var content = JsonArray()
    var textContent = JsonObject()
    textContent.addProperty("type", "text")
    textContent.addProperty("text", toolResult.toString())
    content.add(textContent)

    mcpResponse.add("content", content)
    mcpResponse.addProperty("isError", false)

    // 元の結果をstructuredContentとして保持（オプション）
    mcpResponse.add("structuredContent", toolResult)

    return mcpResponse
  }
}
