package packetproxy.extensions.mcp.tools

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Random
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern
import packetproxy.controller.ResendController
import packetproxy.controller.ResendController.ResendWorker
import packetproxy.model.Configs
import packetproxy.model.OneShotPacket
import packetproxy.model.Packet
import packetproxy.model.Packets
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

/** 複数パケット一括送信ツール フェーズ2: 順次送信モード、modifications適用、regex_params機能 */
class BulkSendTool(
  private val packets: Packets,
  private val resendController: ResendController,
  configs: Configs,
) : AuthenticatedMCPTool(configs) {

  override fun getName(): String = "bulk_send"

  override fun getDescription(): String =
    "Send multiple packets in bulk with optional modifications. " +
      "Use packet_ids array to specify which packets to send (can repeat same ID for multiple variations). " +
      "Use regex_params to apply different modifications to each packet based on packet_index (0-based). " +
      "For full header replacement, use patterns like 'User-Agent: [^\\r\\n]*'. " +
      "For partial replacement, use capture groups like 'Content-Length: ([0-9]+)'. " +
      "The value_template supports variables like {{timestamp}}, {{random}}, {{uuid}}, {{packet_index}}. " +
      "Note: avoid using both packet_ids array with duplicates AND count parameter simultaneously to prevent unexpected multiplication of packets."

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    // packet_ids (required)
    var packetIdsProp = JsonObject()
    packetIdsProp.addProperty("type", "array")
    packetIdsProp.addProperty("description", "Array of packet IDs to send (1-100 packets)")
    var packetIdsItems = JsonObject()
    packetIdsItems.addProperty("type", "integer")
    packetIdsProp.add("items", packetIdsItems)
    schema.add("packet_ids", packetIdsProp)

    // mode (optional)
    var modeProp = JsonObject()
    modeProp.addProperty("type", "string")
    var modeEnum = JsonArray()
    modeEnum.add("parallel")
    modeEnum.add("sequential")
    modeProp.add("enum", modeEnum)
    modeProp.addProperty("description", "Sending mode: parallel (fast) or sequential (controlled)")
    modeProp.addProperty("default", "parallel")
    schema.add("mode", modeProp)

    // count (optional)
    var countProp = JsonObject()
    countProp.addProperty("type", "integer")
    countProp.addProperty("description", "Number of times to send each packet (default: 1)")
    countProp.addProperty("default", 1)
    countProp.addProperty("minimum", 1)
    countProp.addProperty("maximum", 1000)
    schema.add("count", countProp)

    // interval_ms (optional)
    var intervalProp = JsonObject()
    intervalProp.addProperty("type", "integer")
    intervalProp.addProperty(
      "description",
      "Interval between sends in milliseconds (sequential mode only, default: 0, maximum: 60000)",
    )
    intervalProp.addProperty("default", 0)
    intervalProp.addProperty("minimum", 0)
    intervalProp.addProperty("maximum", 60000)
    schema.add("interval_ms", intervalProp)

    // regex_params (optional)
    var regexParamsProp = JsonObject()
    regexParamsProp.addProperty("type", "array")
    regexParamsProp.addProperty(
      "description",
      "Regex parameters for dynamic value replacement across packets",
    )
    var regexParamItem = JsonObject()
    regexParamItem.addProperty("type", "object")
    var regexParamProps = JsonObject()

    var packetIndexProp = JsonObject()
    packetIndexProp.addProperty("type", "integer")
    packetIndexProp.addProperty("description", "Target packet index (0-based)")
    regexParamProps.add("packet_index", packetIndexProp)

    var regexPatternProp = JsonObject()
    regexPatternProp.addProperty("type", "string")
    regexPatternProp.addProperty("description", "Regex pattern to match")
    regexParamProps.add("pattern", regexPatternProp)

    var valueTemplateProp = JsonObject()
    valueTemplateProp.addProperty("type", "string")
    valueTemplateProp.addProperty(
      "description",
      "Template with variables: {{packet_index}}, {{timestamp}}, {{random}}, {{uuid}}",
    )
    regexParamProps.add("value_template", valueTemplateProp)

    var regexTargetProp = JsonObject()
    regexTargetProp.addProperty("type", "string")
    var regexTargetEnum = JsonArray()
    regexTargetEnum.add("request")
    regexTargetEnum.add("response")
    regexTargetEnum.add("both")
    regexTargetProp.add("enum", regexTargetEnum)
    regexTargetProp.addProperty(
      "description",
      "Target: request, response, or both (default: request)",
    )
    regexTargetProp.addProperty("default", "request")
    regexParamProps.add("target", regexTargetProp)

    regexParamItem.add("properties", regexParamProps)
    regexParamsProp.add("items", regexParamItem)
    schema.add("regex_params", regexParamsProp)

    // modifications (optional) - ResendPacketToolと同じ形式
    var modificationsProp = JsonObject()
    modificationsProp.addProperty("type", "array")
    modificationsProp.addProperty(
      "description",
      "Array of modification rules to apply to all packets",
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

    // allow_duplicate_headers (optional)
    var allowDuplicateHeadersProp = JsonObject()
    allowDuplicateHeadersProp.addProperty("type", "boolean")
    allowDuplicateHeadersProp.addProperty(
      "description",
      "Allow duplicate headers when adding/modifying headers (default: false - replace existing headers)",
    )
    allowDuplicateHeadersProp.addProperty("default", false)
    schema.add("allow_duplicate_headers", allowDuplicateHeadersProp)

    // timeout_ms (optional)
    var timeoutProp = JsonObject()
    timeoutProp.addProperty("type", "integer")
    timeoutProp.addProperty(
      "description",
      "Timeout for entire bulk operation in milliseconds (default: 30000)",
    )
    timeoutProp.addProperty("default", 30000)
    timeoutProp.addProperty("minimum", 1000)
    timeoutProp.addProperty("maximum", 300000)
    schema.add("timeout_ms", timeoutProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("BulkSendTool called with arguments: " + getSafeArgumentsString(arguments))
    log("BulkSendTool: Starting bulk send operation")

    // パラメータ取得
    if (!arguments.has("packet_ids")) {
      throw IllegalArgumentException("packet_ids parameter is required")
    }

    var packetIdsArray = arguments.getAsJsonArray("packet_ids")
    if (packetIdsArray.size() == 0) {
      throw IllegalArgumentException("packet_ids array cannot be empty")
    }
    if (packetIdsArray.size() > 100) {
      throw IllegalArgumentException("packet_ids array cannot exceed 100 packets")
    }

    var mode = if (arguments.has("mode")) arguments.get("mode").getAsString() else "parallel"
    var count = if (arguments.has("count")) arguments.get("count").getAsInt() else 1
    var intervalMs =
      if (arguments.has("interval_ms")) arguments.get("interval_ms").getAsInt() else 0
    var allowDuplicateHeaders =
      if (arguments.has("allow_duplicate_headers"))
        arguments.get("allow_duplicate_headers").getAsBoolean()
      else false
    var timeoutMs =
      if (arguments.has("timeout_ms")) arguments.get("timeout_ms").getAsInt() else 30000

    var modifications =
      if (arguments.has("modifications")) arguments.getAsJsonArray("modifications") else JsonArray()

    var regexParams =
      if (arguments.has("regex_params")) arguments.getAsJsonArray("regex_params") else JsonArray()

    // 送信モードの検証
    if (mode != "parallel" && mode != "sequential") {
      throw IllegalArgumentException("mode must be 'parallel' or 'sequential'")
    }

    // 順次送信の場合、interval_msをチェック
    if (mode == "sequential" && intervalMs < 0) {
      throw IllegalArgumentException("interval_ms must be non-negative for sequential mode")
    }

    log(
      "BulkSendTool: packet_ids=" +
        packetIdsArray.size() +
        ", mode=$mode, count=$count, interval=${intervalMs}ms, allowDuplicateHeaders=$allowDuplicateHeaders, timeout=${timeoutMs}ms, modifications=" +
        modifications.size() +
        ", regex_params=" +
        regexParams.size()
    )

    // パケットIDを取得
    var packetIds = ArrayList<Int>()
    for (element in packetIdsArray) {
      packetIds.add(element.getAsInt())
    }

    // ジョブIDを生成
    var jobId = UUID.randomUUID().toString()

    var startTime = System.currentTimeMillis()
    var totalPackets = packetIds.size
    var totalCount = totalPackets * count
    var sentCount = 0
    var failedCount = 0
    var results = ArrayList<BulkSendResult>()
    var regexParamsApplied = ArrayList<RegexParamApplied>()
    var extractedValues = HashMap<String, String>() // regex_paramsで抽出された値を保存

    try {
      if (mode == "parallel") {
        // 並列送信
        for (i in packetIds.indices) {
          var packetId = packetIds[i]
          var result =
            processSinglePacket(
              packetId,
              i,
              count,
              modifications,
              regexParams,
              extractedValues,
              allowDuplicateHeaders,
              jobId,
            )
          results.add(result)
          sentCount += result.sentCount
          failedCount += result.failedCount
          regexParamsApplied.addAll(result.regexParamsApplied!!)
        }
      } else {
        // 順次送信
        for (i in packetIds.indices) {
          var packetId = packetIds[i]
          var result =
            processSinglePacketSequential(
              packetId,
              i,
              count,
              modifications,
              regexParams,
              extractedValues,
              allowDuplicateHeaders,
              intervalMs,
              jobId,
            )
          results.add(result)
          sentCount += result.sentCount
          failedCount += result.failedCount
          regexParamsApplied.addAll(result.regexParamsApplied!!)

          // 次のパケットまでインターバル（最後のパケット以外）
          if (intervalMs > 0 && i < packetIds.size - 1) {
            Thread.sleep(intervalMs.toLong())
          }
        }
      }
    } catch (e: Exception) {
      log("BulkSendTool: Bulk send operation failed: " + e.message)
      throw e
    }

    var executionTime = System.currentTimeMillis() - startTime

    // 結果作成
    var result = JsonObject()
    result.addProperty("success", failedCount == 0)
    result.addProperty("mode", mode)
    result.addProperty("total_packets", totalPackets)
    result.addProperty("total_count", totalCount)
    result.addProperty("sent_count", sentCount)
    result.addProperty("failed_count", failedCount)
    result.addProperty("execution_time_ms", executionTime)

    // 詳細結果
    var resultsArray = JsonArray()
    for (r in results) {
      var resultObj = JsonObject()
      resultObj.addProperty("original_packet_id", r.originalPacketId)
      resultObj.addProperty("packet_index", r.packetIndex)
      resultObj.addProperty("success", r.success)
      resultObj.addProperty("sent_count", r.sentCount)
      resultObj.addProperty("failed_count", r.failedCount)

      if (r.error != null) {
        resultObj.addProperty("error", r.error)
      }
      resultObj.addProperty("execution_time_ms", r.executionTimeMs)

      resultsArray.add(resultObj)
    }
    result.add("results", resultsArray)

    // regex_params適用結果
    var regexParamsAppliedArray = JsonArray()
    for (rpa in regexParamsApplied) {
      var rpaObj = JsonObject()
      rpaObj.addProperty("packet_index", rpa.packetIndex)
      rpaObj.addProperty("pattern", rpa.pattern)
      rpaObj.addProperty("extracted_value", rpa.extractedValue)
      rpaObj.addProperty("applied_count", rpa.appliedCount)
      regexParamsAppliedArray.add(rpaObj)
    }
    result.add("regex_params_applied", regexParamsAppliedArray)

    // パフォーマンス統計
    var performance = JsonObject()
    var packetsPerSecond =
      if (totalCount > 0) sentCount.toDouble() / (executionTime / 1000.0) else 0.0
    var avgResponseTime =
      if (results.isNotEmpty()) results.map { it.executionTimeMs }.average() else 0.0

    performance.addProperty("packets_per_second", Math.round(packetsPerSecond * 100.0) / 100.0)
    performance.addProperty("average_response_time_ms", Math.round(avgResponseTime))
    performance.addProperty("concurrent_connections", totalPackets)
    result.add("performance", performance)

    result.addProperty("job_id", jobId)

    log("BulkSendTool: Completed. Sent: $sentCount, Failed: $failedCount, Time: ${executionTime}ms")
    return result
  }

  /** 単一パケットの処理（並列送信） */
  private fun processSinglePacket(
    packetId: Int,
    packetIndex: Int,
    count: Int,
    modifications: JsonArray,
    regexParams: JsonArray,
    extractedValues: MutableMap<String, String>,
    allowDuplicateHeaders: Boolean,
    jobId: String,
  ): BulkSendResult {
    var result = BulkSendResult()
    result.originalPacketId = packetId
    result.packetIndex = packetIndex
    result.regexParamsApplied = ArrayList()

    var startTime = System.currentTimeMillis()

    try {
      // パケットを取得
      var originalPacket = packets.query(packetId)
      if (originalPacket == null) {
        result.success = false
        result.failedCount = count
        result.error = "Packet with ID $packetId not found"
        return result
      }

      // OneShotPacketを作成
      var originalOneShot = createOneShotPacket(originalPacket)
      if (originalOneShot == null) {
        result.success = false
        result.failedCount = count
        result.error = "Cannot create OneShotPacket from packet ID $packetId"
        return result
      }

      // regex_paramsを適用
      var regexModifiedPacket =
        applyRegexParams(
          originalOneShot,
          regexParams,
          packetIndex,
          extractedValues,
          result.regexParamsApplied!!,
        )

      // modificationsを適用
      var modifiedPacket =
        applyModifications(
          regexModifiedPacket,
          modifications,
          packetIndex + 1,
          allowDuplicateHeaders,
        )

      // 複数回送信用のパケット配列を作成（各パケットに固有のtemporary_idを付与）
      var packetsToSend =
        Array(count) { i ->
          var temporaryId = UUID.randomUUID().toString()
          OneShotPacket(
            modifiedPacket.getId(),
            modifiedPacket.getListenPort(),
            modifiedPacket.getClient(),
            modifiedPacket.getServer(),
            modifiedPacket.getServerName()!!,
            modifiedPacket.getUseSSL(),
            modifiedPacket.getData(),
            modifiedPacket.getEncoder()!!,
            modifiedPacket.getAlpn()!!,
            modifiedPacket.getDirection()!!,
            modifiedPacket.getConn(),
            modifiedPacket.getGroup(),
            jobId,
            temporaryId,
          )
        }

      // ResendControllerを使用して並列送信
      var latch = CountDownLatch(1)
      var receivedPackets = ArrayList<OneShotPacket>()
      var sendErrors = ArrayList<Exception>()

      resendController.resend(
        resendController.run {
          object : ResendWorker(packetsToSend) {
            override fun process(chunks: MutableList<OneShotPacket>) {
              synchronized(receivedPackets) { receivedPackets.addAll(chunks) }
            }

            override fun done() {
              try {
                get() // 例外があれば取得
              } catch (e: Exception) {
                synchronized(sendErrors) { sendErrors.add(e) }
              }
              latch.countDown()
            }
          }
        }
      )

      // 完了を待機
      var completed = latch.await(30, TimeUnit.SECONDS)
      if (!completed) {
        result.success = false
        result.failedCount = count
        result.error = "Timeout waiting for packet sending completion"
        return result
      }

      // 結果を設定
      if (sendErrors.isNotEmpty()) {
        result.success = false
        result.failedCount = count
        result.error = "Send failed: " + sendErrors[0].message
      } else {
        result.success = true
        result.sentCount = count
      }
    } catch (e: Exception) {
      result.success = false
      result.failedCount = count
      result.error = e.message
      log("BulkSendTool: Failed to process packet $packetId: " + e.message)
    } finally {
      result.executionTimeMs = System.currentTimeMillis() - startTime
    }

    return result
  }

  /** 単一パケットの処理（順次送信） */
  private fun processSinglePacketSequential(
    packetId: Int,
    packetIndex: Int,
    count: Int,
    modifications: JsonArray,
    regexParams: JsonArray,
    extractedValues: MutableMap<String, String>,
    allowDuplicateHeaders: Boolean,
    intervalMs: Int,
    jobId: String,
  ): BulkSendResult {
    var result = BulkSendResult()
    result.originalPacketId = packetId
    result.packetIndex = packetIndex
    result.regexParamsApplied = ArrayList()

    var startTime = System.currentTimeMillis()

    try {
      // パケットを取得
      var originalPacket = packets.query(packetId)
      if (originalPacket == null) {
        result.success = false
        result.failedCount = count
        result.error = "Packet with ID $packetId not found"
        return result
      }

      // OneShotPacketを作成
      var originalOneShot = createOneShotPacket(originalPacket)
      if (originalOneShot == null) {
        result.success = false
        result.failedCount = count
        result.error = "Cannot create OneShotPacket from packet ID $packetId"
        return result
      }

      // 順次送信の場合、各送信で異なる処理を実行
      var successCount = 0
      var failCount = 0

      for (i in 0 until count) {
        try {
          // regex_paramsを適用（送信回数も考慮）
          var regexModifiedPacket =
            applyRegexParams(
              originalOneShot,
              regexParams,
              packetIndex,
              extractedValues,
              result.regexParamsApplied!!,
            )

          // modificationsを適用
          var modifiedPacket =
            applyModifications(
              regexModifiedPacket,
              modifications,
              packetIndex * count + i + 1,
              allowDuplicateHeaders,
            )

          // ジョブ情報を付与
          var temporaryId = UUID.randomUUID().toString()
          var jobPacket =
            OneShotPacket(
              modifiedPacket.getId(),
              modifiedPacket.getListenPort(),
              modifiedPacket.getClient(),
              modifiedPacket.getServer(),
              modifiedPacket.getServerName()!!,
              modifiedPacket.getUseSSL(),
              modifiedPacket.getData(),
              modifiedPacket.getEncoder()!!,
              modifiedPacket.getAlpn()!!,
              modifiedPacket.getDirection()!!,
              modifiedPacket.getConn(),
              modifiedPacket.getGroup(),
              jobId,
              temporaryId,
            )

          // 単発送信
          resendController.resend(jobPacket)
          successCount++

          // 同一パケット内の送信間隔
          if (intervalMs > 0 && i < count - 1) {
            Thread.sleep(intervalMs.toLong())
          }
        } catch (e: Exception) {
          log(
            "BulkSendTool: Failed to send packet $packetId (attempt " + (i + 1) + "): " + e.message
          )
          failCount++
        }
      }

      result.success = failCount == 0
      result.sentCount = successCount
      result.failedCount = failCount
    } catch (e: Exception) {
      result.success = false
      result.failedCount = count
      result.error = e.message
      log("BulkSendTool: Failed to process packet $packetId: " + e.message)
    } finally {
      result.executionTimeMs = System.currentTimeMillis() - startTime
    }

    return result
  }

  /** OneShotPacketを作成（ResendPacketToolと同じロジック） */
  @Throws(Exception::class)
  private fun createOneShotPacket(originalPacket: Packet): OneShotPacket? {
    return if (originalPacket.getModifiedData().isNotEmpty()) {
      originalPacket.getOneShotFromModifiedData()
    } else if (originalPacket.getSentData().isNotEmpty()) {
      originalPacket.getOneShotPacket(originalPacket.getSentData())
    } else {
      originalPacket.getOneShotFromDecodedData()
    }
  }

  /** regex_paramsを適用 */
  @Throws(Exception::class)
  private fun applyRegexParams(
    original: OneShotPacket,
    regexParams: JsonArray,
    packetIndex: Int,
    extractedValues: MutableMap<String, String>,
    appliedList: MutableList<RegexParamApplied>,
  ): OneShotPacket {
    if (regexParams.size() == 0) {
      return original
    }

    log(
      "BulkSendTool: Applying " +
        regexParams.size() +
        " regex params to packet (index=$packetIndex)"
    )

    var data = original.getData().clone()
    var dataStr = String(data)

    for (paramElement in regexParams) {
      var param = paramElement.getAsJsonObject()

      // packet_indexが指定されている場合、対象パケットかチェック
      if (param.has("packet_index") && param.get("packet_index").getAsInt() != packetIndex) {
        continue
      }

      var pattern = param.get("pattern").getAsString()
      var valueTemplate = param.get("value_template").getAsString()
      var target = if (param.has("target")) param.get("target").getAsString() else "request"

      // 値テンプレートを処理
      var processedValue = processValueTemplate(valueTemplate, packetIndex, extractedValues)

      try {
        var regex = Pattern.compile(pattern)
        var matcher = regex.matcher(dataStr)

        if (matcher.find()) {
          // マッチした値を抽出（後続パケットで使用可能）
          var extractedValue: String? = null
          try {
            // キャプチャグループがあるかチェック
            extractedValue =
              if (matcher.groupCount() > 0) {
                matcher.group(1)
              } else {
                // キャプチャグループがない場合は全体をマッチ
                matcher.group(0)
              }

            if (extractedValue != null) {
              var key = "packet_" + packetIndex + "_" + pattern
              extractedValues[key] = extractedValue
            }
          } catch (ex: Exception) {
            log("BulkSendTool: Failed to extract value: " + ex.message)
          }

          // 置換実行
          var beforeReplace = dataStr
          dataStr = matcher.replaceAll(processedValue)

          // デバッグログ: 置換前後の比較
          if (beforeReplace != dataStr) {
            log("BulkSendTool: Replacement successful - pattern: $pattern")
            log(
              "BulkSendTool: Before: " +
                beforeReplace.substring(
                  maxOf(0, matcher.start() - 20),
                  minOf(beforeReplace.length, matcher.end() + 20),
                )
            )
            log(
              "BulkSendTool: After: " +
                dataStr.substring(
                  maxOf(0, dataStr.indexOf(processedValue) - 20),
                  minOf(
                    dataStr.length,
                    dataStr.indexOf(processedValue) + processedValue.length + 20,
                  ),
                )
            )
          } else {
            log("BulkSendTool: Warning: No replacement occurred for pattern: $pattern")
          }

          // 適用結果を記録
          var applied = RegexParamApplied()
          applied.packetIndex = packetIndex
          applied.pattern = pattern
          applied.extractedValue = extractedValue
          applied.appliedCount = 1
          appliedList.add(applied)

          log("BulkSendTool: Regex param applied - pattern: $pattern, value: $processedValue")
        } else {
          log("BulkSendTool: Pattern not found in data - pattern: $pattern")
          // デバッグ用: データの一部を表示
          var debugData = if (dataStr.length > 200) dataStr.substring(0, 200) + "..." else dataStr
          log("BulkSendTool: Data sample: " + debugData.replace("\r\n", "\\r\\n"))
        }
      } catch (e: Exception) {
        log("BulkSendTool: Regex param failed: " + e.message)
        errWithStackTrace(e)
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
    )
  }

  /** value_templateを処理（ResendPacketToolのprocessReplacementVariablesを拡張） */
  private fun processValueTemplate(
    template: String,
    packetIndex: Int,
    extractedValues: Map<String, String>,
  ): String {
    var result = template

    // {{packet_index}} - パケットインデックス
    result = result.replace("{{packet_index}}", packetIndex.toString())

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

    // 抽出された値を置換（{{extracted:key}}形式）
    for ((key, value) in extractedValues) {
      var placeholder = "{{extracted:$key}}"
      result = result.replace(placeholder, value)
    }

    return result
  }

  /** パケットに改変を適用（ResendPacketToolのロジックを完全実装） */
  @Throws(Exception::class)
  private fun applyModifications(
    original: OneShotPacket,
    modifications: JsonArray,
    index: Int,
    allowDuplicateHeaders: Boolean,
  ): OneShotPacket {
    if (modifications.size() == 0) {
      return original
    }

    log(
      "BulkSendTool: Applying " + modifications.size() + " modifications to packet (index=$index)"
    )

    var data = original.getData().clone()
    var dataStr = String(data)

    for (modElement in modifications) {
      var modification = modElement.getAsJsonObject()

      var target =
        if (modification.has("target")) modification.get("target").getAsString() else "request"
      var type = modification.get("type").getAsString()

      log("BulkSendTool: Applying modification type=$type, target=$target")

      when (type) {
        "regex_replace" -> dataStr = applyRegexReplace(dataStr, modification, index)
        "header_add" ->
          dataStr = applyHeaderAdd(dataStr, modification, index, allowDuplicateHeaders)
        "header_modify" ->
          dataStr = applyHeaderModify(dataStr, modification, index, allowDuplicateHeaders)
        else -> log("BulkSendTool: Unknown modification type: $type")
      }
    }

    data = dataStr.toByteArray()

    // 新しいOneShotPacketを作成（job情報は後で付与）
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
    )
  }

  /** 正規表現置換を適用（ResendPacketToolから移植） */
  private fun applyRegexReplace(data: String, modification: JsonObject, index: Int): String {
    var pattern = modification.get("pattern").getAsString()
    var replacement = modification.get("replacement").getAsString()

    // 置換変数を処理
    replacement = processReplacementVariables(replacement, index)

    try {
      var regex = Pattern.compile(pattern)
      var matcher = regex.matcher(data)
      var result = matcher.replaceAll(replacement)
      log("BulkSendTool: Regex replace applied - pattern: $pattern, replacement: $replacement")
      return result
    } catch (e: Exception) {
      log("BulkSendTool: Regex replace failed: " + e.message)
      return data
    }
  }

  /** ヘッダー追加を適用（ResendPacketToolから移植） */
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
        log("BulkSendTool: Header replaced (no duplicates allowed) - $name: $value")
        return result
      }
    }

    // 新しいヘッダーを追加
    var newHeader = "$name: $value\r\n"
    var result = headers + "\r\n" + newHeader + body
    log("BulkSendTool: Header added - $name: $value")
    return result
  }

  /** ヘッダー変更を適用（ResendPacketToolから移植） */
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
          "BulkSendTool: Header modified - $name: $value (allowDuplicates=$allowDuplicateHeaders)"
        )
        return result
      }
      // ヘッダーが見つからない場合は追加
      return applyHeaderAdd(data, modification, index, allowDuplicateHeaders)
    } catch (e: Exception) {
      log("BulkSendTool: Header modify failed: " + e.message)
      return data
    }
  }

  /** 置換変数を処理（ResendPacketToolから移植） */
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

  /** ランダム文字列生成（ResendPacketToolから移植） */
  private fun generateRandomString(length: Int): String {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    var random = Random()
    var sb = StringBuilder()

    for (i in 0 until length) {
      sb.append(chars[random.nextInt(chars.length)])
    }

    return sb.toString()
  }

  /** 個別パケットの送信結果 */
  private class BulkSendResult {
    var originalPacketId = 0
    var packetIndex = 0
    var success = false
    var sentCount = 0
    var failedCount = 0
    var error: String? = null
    var executionTimeMs: Long = 0
    var regexParamsApplied: MutableList<RegexParamApplied>? = null
  }

  /** regex_paramsの適用結果 */
  private class RegexParamApplied {
    var packetIndex = 0
    var pattern: String? = null
    var extractedValue: String? = null
    var appliedCount = 0
  }
}
