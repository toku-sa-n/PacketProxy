package packetproxy.extensions.mcp.tools

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import packetproxy.CoreServices
import packetproxy.gui.GUIResender

class ToolRegistry(private val coreServices: CoreServices, private val guiResender: GUIResender) {

  private val tools: MutableMap<String, MCPTool>

  init {
    this.tools = HashMap()
    registerDefaultTools()
  }

  private fun registerDefaultTools() {
    // 基本的なツールを登録
    val configs = coreServices.modelServices.configs
    val modifications = coreServices.modelServices.modifications
    val servers = coreServices.modelServices.servers
    registerTool(HistoryTool(coreServices.modelServices.packets, configs))
    registerTool(PacketDetailTool(coreServices.modelServices.packets, configs))
    registerTool(LogTool(configs))
    registerTool(ConfigTool(configs))
    registerTool(UpdateConfigTool(configs))
    registerTool(RestoreConfigTool(configs))
    registerTool(
      ResendPacketTool(coreServices.modelServices.packets, coreServices.resendController, configs)
    )
    registerTool(
      BulkSendTool(coreServices.modelServices.packets, coreServices.resendController, configs)
    )
    registerTool(
      VulCheckHelperTool(
        coreServices.modelServices.packets,
        coreServices.vulCheckerManager,
        coreServices.resendController,
        configs,
      )
    )
    registerTool(JobStatusTool(coreServices.modelServices.packets, configs))
    registerTool(CreateResenderTabHttp2Tool(coreServices.uniqueId, guiResender, configs))
    registerTool(ListModificationsTool(modifications, servers, configs))
    registerTool(CreateModificationTool(modifications, servers, configs))
    registerTool(UpdateModificationTool(modifications, servers, configs))
    registerTool(DeleteModificationTool(modifications, configs))
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
