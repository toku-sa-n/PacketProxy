package packetproxy.extensions.mcp.tools

import com.google.gson.JsonObject

interface MCPTool {

  /** ツール名を取得 */
  fun getName(): String

  /** ツールの説明を取得 */
  fun getDescription(): String

  /** 入力スキーマを取得 (JSON Schema properties形式) */
  fun getInputSchema(): JsonObject

  /** ツールを実行 */
  @Throws(Exception::class) fun call(arguments: JsonObject): JsonObject
}
