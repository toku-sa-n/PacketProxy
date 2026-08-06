package packetproxy.extensions.mcp.tools

import com.google.gson.JsonObject
import packetproxy.model.ConfigString
import packetproxy.util.log

/** 認証機能付きMCPツールの基底クラス */
abstract class AuthenticatedMCPTool(protected val configs: packetproxy.model.Configs) : MCPTool {

  /** AccessTokenの検証を行う */
  @Throws(Exception::class)
  protected fun validateAccessToken(arguments: JsonObject) {
    if (!arguments.has("access_token")) {
      throw Exception(
        "access_token parameter is required. Please provide your PacketProxy access token from Settings."
      )
    }

    var providedToken: String? = arguments.get("access_token").getAsString()
    if (providedToken == null || providedToken.trim().isEmpty()) {
      throw Exception(
        "access_token parameter is required and must match the configured PacketProxy access token. Empty tokens are not accepted."
      )
    }

    var configuredToken = ConfigString(configs, "SharingConfigsAccessToken").getString()
    if (configuredToken.isEmpty()) {
      throw Exception(
        "Access token not configured in PacketProxy. Please enable 'Import/Export configs' in PacketProxy Settings and copy the generated access token."
      )
    }

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
      "PacketProxy access token from Settings > Import/Export configs. Must match the configured token; empty values are rejected.",
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
