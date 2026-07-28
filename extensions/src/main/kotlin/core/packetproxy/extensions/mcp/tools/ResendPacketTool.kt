package packetproxy.extensions.mcp.tools

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Random
import java.util.UUID
import java.util.regex.Pattern
import packetproxy.controller.ResendController
import packetproxy.model.Configs
import packetproxy.model.OneShotPacket
import packetproxy.model.Packets
import packetproxy.util.log

/** パケット再送ツール パケットを指定回数再送し、改変オプションもサポート */
class ResendPacketTool(
  private val packets: Packets,
  private val resendController: ResendController,
  configs: Configs,
) : AuthenticatedMCPTool(configs) {

  override fun getName(): String = "resend_packet"

  override fun getDescription(): String =
    "Resend a packet with optional modifications and multiple count support"

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var packetIdProp = JsonObject()
    packetIdProp.addProperty("type", "integer")
    packetIdProp.addProperty("description", "ID of the packet to resend")
    schema.add("packet_id", packetIdProp)

    var countProp = JsonObject()
    countProp.addProperty("type", "integer")
    countProp.addProperty("description", "Number of times to send the packet (default: 1)")
    countProp.addProperty("default", 1)
    schema.add("count", countProp)

    var intervalProp = JsonObject()
    intervalProp.addProperty("type", "integer")
    intervalProp.addProperty("description", "Interval between sends in milliseconds (default: 0)")
    intervalProp.addProperty("default", 0)
    schema.add("interval_ms", intervalProp)

    var modificationsProp = JsonObject()
    modificationsProp.addProperty("type", "array")
    modificationsProp.addProperty(
      "description",
      "Array of modification rules to apply to the packet",
    )
    var modificationItem = JsonObject()
    modificationItem.addProperty("type", "object")
    var modificationProps = JsonObject()

    var targetProp = JsonObject()
    targetProp.addProperty("type", "string")
    var targetEnum = JsonArray()
    targetEnum.add("request")
    targetEnum.add("response")
    targetEnum.add("both")
    targetProp.add("enum", targetEnum)
    targetProp.addProperty("description", "Target to modify: request, response, or both")
    modificationProps.add("target", targetProp)

    var typeProp = JsonObject()
    typeProp.addProperty("type", "string")
    var typeEnum = JsonArray()
    typeEnum.add("regex_replace")
    typeEnum.add("header_add")
    typeEnum.add("header_modify")
    typeProp.add("enum", typeEnum)
    typeProp.addProperty("description", "Type of modification")
    modificationProps.add("type", typeProp)

    var patternProp = JsonObject()
    patternProp.addProperty("type", "string")
    patternProp.addProperty("description", "Regex pattern for regex_replace type")
    modificationProps.add("pattern", patternProp)

    var replacementProp = JsonObject()
    replacementProp.addProperty("type", "string")
    replacementProp.addProperty(
      "description",
      "Replacement string for regex_replace or value for headers",
    )
    modificationProps.add("replacement", replacementProp)

    var nameProp = JsonObject()
    nameProp.addProperty("type", "string")
    nameProp.addProperty("description", "Header name for header_add/header_modify")
    modificationProps.add("name", nameProp)

    var valueProp = JsonObject()
    valueProp.addProperty("type", "string")
    valueProp.addProperty("description", "Header value for header_add/header_modify")
    modificationProps.add("value", valueProp)

    modificationItem.add("properties", modificationProps)
    modificationsProp.add("items", modificationItem)
    schema.add("modifications", modificationsProp)

    var asyncProp = JsonObject()
    asyncProp.addProperty("type", "boolean")
    asyncProp.addProperty("description", "Execute asynchronously (default: false)")
    asyncProp.addProperty("default", false)
    schema.add("async", asyncProp)

    var allowDuplicateHeadersProp = JsonObject()
    allowDuplicateHeadersProp.addProperty("type", "boolean")
    allowDuplicateHeadersProp.addProperty(
      "description",
      "Allow duplicate headers when adding/modifying headers (default: false - replace existing headers)",
    )
    allowDuplicateHeadersProp.addProperty("default", false)
    schema.add("allow_duplicate_headers", allowDuplicateHeadersProp)

    // access_tokenを追加
    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("ResendPacketTool called with arguments: " + getSafeArgumentsString(arguments))
    log("ResendPacketTool: Starting packet resend operation")

    // パラメータ取得
    if (!arguments.has("packet_id")) {
      throw IllegalArgumentException("packet_id parameter is required")
    }

    var packetId = arguments.get("packet_id").getAsInt()
    var count = if (arguments.has("count")) arguments.get("count").getAsInt() else 1
    var intervalMs =
      if (arguments.has("interval_ms")) arguments.get("interval_ms").getAsInt() else 0
    var async = if (arguments.has("async")) arguments.get("async").getAsBoolean() else false
    var allowDuplicateHeaders =
      if (arguments.has("allow_duplicate_headers"))
        arguments.get("allow_duplicate_headers").getAsBoolean()
      else false

    var modifications =
      if (arguments.has("modifications")) arguments.getAsJsonArray("modifications") else JsonArray()

    log(
      "ResendPacketTool: packet_id=$packetId, count=$count, interval=${intervalMs}ms, async=$async, allowDuplicateHeaders=$allowDuplicateHeaders"
    )

    // パケットを取得
    var originalPacket = packets.query(packetId)
    if (originalPacket == null) {
      throw IllegalArgumentException("Packet with ID $packetId not found")
    }

    // 適切なデータを使ってOneShotPacketを作成
    // 改変データがあれば改変データを、なければ送信データを使用
    var originalOneShot =
      if (originalPacket.getModifiedData().isNotEmpty()) {
        originalPacket.getOneShotFromModifiedData()
      } else if (originalPacket.getSentData().isNotEmpty()) {
        originalPacket.getOneShotPacket(originalPacket.getSentData())
      } else {
        // デコードされたデータをフォールバックとして使用
        originalPacket.getOneShotFromDecodedData()
      }

    if (originalOneShot == null) {
      throw IllegalArgumentException("Cannot create OneShotPacket from packet ID $packetId")
    }

    log("ResendPacketTool: Original packet found, preparing for resend")

    // ジョブIDを生成
    var jobId = UUID.randomUUID().toString()

    var startTime = System.currentTimeMillis()
    var sentCount = 0
    var failedCount = 0

    try {
      if (modifications.size() == 0) {
        // 改変なしの場合は単純再送
        log("ResendPacketTool: Simple resend without modifications, count=$count")
        for (i in 0 until count) {
          var temporaryId = UUID.randomUUID().toString()
          var jobPacket =
            OneShotPacket(
              originalOneShot.getId(),
              originalOneShot.getListenPort(),
              originalOneShot.getClient(),
              originalOneShot.getServer(),
              originalOneShot.getServerName()!!,
              originalOneShot.getUseSSL(),
              originalOneShot.getData(),
              originalOneShot.getEncoder()!!,
              originalOneShot.getAlpn()!!,
              originalOneShot.getDirection()!!,
              originalOneShot.getConn(),
              originalOneShot.getGroup(),
              jobId,
              temporaryId,
            )
          resendController.resend(jobPacket)
          sentCount++

          // インターバル待機（最後の送信後は待機しない）
          if (intervalMs > 0 && i < count - 1) {
            Thread.sleep(intervalMs.toLong())
          }
        }
      } else {
        // 複数回送信または改変ありの場合
        log(
          "ResendPacketTool: Complex resend with count=$count and modifications=" +
            modifications.size()
        )

        for (i in 0 until count) {
          try {
            var temporaryId = UUID.randomUUID().toString()
            var modifiedPacket =
              applyModifications(
                originalOneShot,
                modifications,
                i + 1,
                allowDuplicateHeaders,
                jobId,
                temporaryId,
              )
            resendController.resend(modifiedPacket)
            sentCount++

            // インターバル待機（最後の送信後は待機しない）
            if (intervalMs > 0 && i < count - 1) {
              Thread.sleep(intervalMs.toLong())
            }
          } catch (e: Exception) {
            log("ResendPacketTool: Failed to send packet " + (i + 1) + ": " + e.message)
            failedCount++
          }
        }
      }
    } catch (e: Exception) {
      log("ResendPacketTool: Resend operation failed: " + e.message)
      failedCount = count - sentCount
      throw e
    }

    var executionTime = System.currentTimeMillis() - startTime

    // 結果作成
    var result = JsonObject()
    result.addProperty("success", failedCount == 0)
    result.addProperty("sent_count", sentCount)
    result.addProperty("failed_count", failedCount)
    result.addProperty("execution_time_ms", executionTime)
    result.addProperty("job_id", jobId)

    log(
      "ResendPacketTool: Completed. Sent: $sentCount, Failed: $failedCount, Time: ${executionTime}ms"
    )
    return result
  }

  /** パケットに改変を適用 */
  @Throws(Exception::class)
  private fun applyModifications(
    original: OneShotPacket,
    modifications: JsonArray,
    index: Int,
    allowDuplicateHeaders: Boolean,
    jobId: String,
    temporaryId: String,
  ): OneShotPacket {
    if (modifications.size() == 0) {
      return original
    }

    log(
      "ResendPacketTool: Applying " +
        modifications.size() +
        " modifications to packet (index=$index)"
    )

    var data = original.getData().clone()
    var dataStr = String(data)

    for (modElement in modifications) {
      var modification = modElement.getAsJsonObject()

      var target =
        if (modification.has("target")) modification.get("target").getAsString() else "request"
      var type = modification.get("type").getAsString()

      log("ResendPacketTool: Applying modification type=$type, target=$target")

      when (type) {
        "regex_replace" -> dataStr = applyRegexReplace(dataStr, modification, index)
        "header_add" ->
          dataStr = applyHeaderAdd(dataStr, modification, index, allowDuplicateHeaders)
        "header_modify" ->
          dataStr = applyHeaderModify(dataStr, modification, index, allowDuplicateHeaders)
        else -> log("ResendPacketTool: Unknown modification type: $type")
      }
    }

    data = dataStr.toByteArray()

    // 新しいOneShotPacketを作成
    return OneShotPacket(
      original.getId(),
      original.getListenPort(),
      original.getClient(),
      original.getServer(),
      original.getServerName()!!,
      original.getUseSSL(),
      data,
      original.getEncoder()!!,
      original.getAlpn()!!,
      original.getDirection()!!,
      original.getConn(),
      original.getGroup(),
      jobId,
      temporaryId,
    )
  }

  /** 正規表現置換を適用 */
  private fun applyRegexReplace(data: String, modification: JsonObject, index: Int): String {
    var pattern = modification.get("pattern").getAsString()
    var replacement = modification.get("replacement").getAsString()

    // 置換変数を処理
    replacement = processReplacementVariables(replacement, index)

    try {
      var regex = Pattern.compile(pattern)
      var matcher = regex.matcher(data)
      var result = matcher.replaceAll(replacement)
      log("ResendPacketTool: Regex replace applied - pattern: $pattern, replacement: $replacement")
      return result
    } catch (e: Exception) {
      log("ResendPacketTool: Regex replace failed: " + e.message)
      return data
    }
  }

  /** ヘッダー追加を適用 */
  private fun applyHeaderAdd(
    data: String,
    modification: JsonObject,
    index: Int,
    allowDuplicateHeaders: Boolean,
  ): String {
    var name = modification.get("name").getAsString()
    var value = modification.get("value").getAsString()

    // 置換変数を処理
    value = processReplacementVariables(value, index)

    // HTTP形式のデータの場合、ヘッダー部分に追加
    if (!data.contains("\r\n\r\n")) {
      return data
    }

    var headerEnd = data.indexOf("\r\n\r\n")
    var headers = data.substring(0, headerEnd)
    var body = data.substring(headerEnd)

    // 重複を許可しない場合、既存ヘッダーがあるかチェック
    if (!allowDuplicateHeaders) {
      var pattern = "(?i)" + Pattern.quote(name) + ":\\s*[^\r\n]*"
      var regex = Pattern.compile(pattern)
      var matcher = regex.matcher(headers)
      if (matcher.find()) {
        // 既存ヘッダーを置換
        var result = matcher.replaceFirst("$name: $value") + body
        log("ResendPacketTool: Header replaced (no duplicates allowed) - $name: $value")
        return result
      }
    }

    // 新しいヘッダーを追加
    var newHeader = "$name: $value\r\n"
    var result = headers + "\r\n" + newHeader + body
    log("ResendPacketTool: Header added - $name: $value")
    return result
  }

  /** ヘッダー変更を適用 */
  private fun applyHeaderModify(
    data: String,
    modification: JsonObject,
    index: Int,
    allowDuplicateHeaders: Boolean,
  ): String {
    var name = modification.get("name").getAsString()
    var value = modification.get("value").getAsString()

    // 置換変数を処理
    value = processReplacementVariables(value, index)

    // 既存ヘッダーを置換
    var pattern = "(?i)" + Pattern.quote(name) + ":\\s*[^\r\n]*"

    try {
      var regex = Pattern.compile(pattern)
      var matcher = regex.matcher(data)
      if (matcher.find()) {
        var replacement = "$name: $value"
        var result =
          if (allowDuplicateHeaders) {
            // 重複を許可する場合は最初のヘッダーのみ変更
            matcher.replaceFirst(replacement)
          } else {
            // 重複を許可しない場合は全ての同名ヘッダーを置換
            matcher.replaceAll(replacement)
          }
        log(
          "ResendPacketTool: Header modified - $name: $value (allowDuplicates=$allowDuplicateHeaders)"
        )
        return result
      }
      // ヘッダーが見つからない場合は追加
      return applyHeaderAdd(data, modification, index, allowDuplicateHeaders)
    } catch (e: Exception) {
      log("ResendPacketTool: Header modify failed: " + e.message)
      return data
    }
  }

  /** 置換変数を処理 */
  private fun processReplacementVariables(input: String, index: Int): String {
    var result = input

    // {{index}} - 送信順序
    result = result.replace("{{index}}", index.toString())

    // {{timestamp}} - Unix timestamp
    result = result.replace("{{timestamp}}", (System.currentTimeMillis() / 1000).toString())

    // {{random}} - ランダム文字列
    if (result.contains("{{random}}")) {
      var randomStr = generateRandomString(8)
      result = result.replace("{{random}}", randomStr)
    }

    // {{uuid}} - UUID v4
    if (result.contains("{{uuid}}")) {
      var uuid = UUID.randomUUID().toString()
      result = result.replace("{{uuid}}", uuid)
    }

    // {{datetime}} - ISO 8601形式日時
    if (result.contains("{{datetime}}")) {
      var datetime = Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT)
      result = result.replace("{{datetime}}", datetime)
    }

    return result
  }

  /** ランダム文字列生成 */
  private fun generateRandomString(length: Int): String {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    var random = Random()
    var sb = StringBuilder()

    for (i in 0 until length) {
      sb.append(chars[random.nextInt(chars.length)])
    }

    return sb.toString()
  }
}
