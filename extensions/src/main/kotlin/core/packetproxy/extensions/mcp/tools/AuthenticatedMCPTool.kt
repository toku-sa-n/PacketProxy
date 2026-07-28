package packetproxy.extensions.mcp.tools

import com.google.gson.JsonObject
import packetproxy.model.ConfigString
import packetproxy.util.log

/** 認証機能付きMCPツールの基底クラス */
abstract class AuthenticatedMCPTool(private val configs: packetproxy.model.Configs) : MCPTool {

  /** AccessTokenの検証を行う */
  @Throws(Exception::class)
  protected fun validateAccessToken(arguments: JsonObject) {
    // MCP clientから渡されたAccessTokenを取得
    if (!arguments.has("access_token")) {
      throw Exception(
        "access_token parameter is required. Please provide your PacketProxy access token from Settings."
      )
    }

    var providedToken: String? = arguments.get("access_token").getAsString()
    if (providedToken == null) {
      throw Exception(
        "access_token parameter is required. Please provide your PacketProxy access token from Settings or leave empty (\"\") to use environment variable."
      )
    }

    // 空文字列の場合は環境変数から取得する想定なのでvalidationをスキップ
    if (providedToken.trim().isEmpty()) {
      log("Empty access_token provided, assuming environment variable usage")
      return
    }

    // PacketProxy設定からAccessTokenを取得
    var configuredToken = ConfigString(configs, "SharingConfigsAccessToken").getString()
    if (configuredToken.isEmpty()) {
      throw Exception(
        "Access token not configured in PacketProxy. Please enable 'Import/Export configs' in PacketProxy Settings and copy the generated access token."
      )
    }

    // トークンの照合
    if (configuredToken != providedToken) {
      log("Access token validation failed")
      throw Exception(
        "Invalid access token. Please check your access token from PacketProxy Settings > Import/Export configs section."
      )
    }

    log("Access token validation successful")
  }

  /** 設定済みAccessTokenを取得（HTTPリクエスト用） */
  @Throws(Exception::class)
  protected fun getConfiguredAccessToken(): String {
    var accessToken = ConfigString(configs, "SharingConfigsAccessToken").getString()
    if (accessToken.isEmpty()) {
      throw Exception("Access token not configured. Please enable config sharing in settings.")
    }
    return accessToken
  }

  /** 入力スキーマにaccess_tokenパラメータを追加 */
  protected fun addAccessTokenToSchema(schema: JsonObject): JsonObject {
    var accessTokenProp = JsonObject()
    accessTokenProp.addProperty("type", "string")
    accessTokenProp.addProperty(
      "description",
      "Access token for authentication. Leave empty (\"\") to use environment variable (handled by scripts/mcp-http-bridge.js), or provide explicit token string",
    )
    schema.add("access_token", accessTokenProp)
    return schema
  }

  /** access_tokenをマスクした安全なargumentsの文字列表現を返す */
  protected fun getSafeArgumentsString(arguments: JsonObject): String {
    var safeArgs = arguments.deepCopy()
    if (safeArgs.has("access_token")) {
      safeArgs.addProperty("access_token", "****")
    }
    return safeArgs.toString()
  }

  /** サブクラスで実装する認証後の実際の処理 */
  @Throws(Exception::class)
  protected abstract fun executeAuthenticated(arguments: JsonObject): JsonObject

  /** 認証チェック付きでツールを実行 */
  @Throws(Exception::class)
  final override fun call(arguments: JsonObject): JsonObject {
    validateAccessToken(arguments)
    return executeAuthenticated(arguments)
  }
}
