package packetproxy.extensions.mcp.tools

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.text.SimpleDateFormat
import java.util.Comparator
import javax.swing.RowFilter
import packetproxy.gui.FilterTextParser
import packetproxy.model.Packet
import packetproxy.model.Packets
import packetproxy.util.Logging.log

class HistoryTool : AuthenticatedMCPTool() {

  private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
  private val gson = Gson()

  override fun getName(): String = "get_history"

  override fun getDescription(): String =
    "Get packet history from PacketProxy with filtering and ordering capabilities"

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var limitProp = JsonObject()
    limitProp.addProperty("type", "integer")
    limitProp.addProperty("description", "Maximum number of packets to return")
    limitProp.addProperty("default", 100)
    schema.add("limit", limitProp)

    var offsetProp = JsonObject()
    offsetProp.addProperty("type", "integer")
    offsetProp.addProperty("description", "Number of packets to skip")
    offsetProp.addProperty("default", 0)
    schema.add("offset", offsetProp)

    var filterProp = JsonObject()
    filterProp.addProperty("type", "string")
    filterProp.addProperty(
      "description",
      "PacketProxy Filter syntax for filtering packets. " +
        "Available columns: id, request, response, length, client_ip, client_port, server_ip, server_port, time, resend, modified, type, encode, alpn, group, full_text, full_text_i. " +
        "Note: method, url, status are NOT available for filtering (only for ordering). " +
        "Operators: == (equals), != (not equals), >= (greater or equal), <= (less or equal), =~ (regex match), !~ (regex not match), && (AND), || (OR). " +
        "Examples: 'type == HTTP', 'length > 1000', 'full_text_i =~ authorization', 'client_port == 80 && server_port == 443'",
    )
    schema.add("filter", filterProp)

    var orderProp = JsonObject()
    orderProp.addProperty("type", "string")
    orderProp.addProperty(
      "description",
      "Order by column and direction. Format: 'column asc' or 'column desc'. " +
        "Available columns: id, length, client_ip, client_port, server_ip, server_port, time, resend, modified, type, encode, group, method, url, status. " +
        "Examples: 'time desc', 'id asc', 'length desc', 'status asc'",
    )
    orderProp.addProperty("default", "id desc")
    schema.add("order", orderProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("HistoryTool called with arguments: " + getSafeArgumentsString(arguments))

    var limit = if (arguments.has("limit")) arguments.get("limit").getAsInt() else 100
    var offset = if (arguments.has("offset")) arguments.get("offset").getAsInt() else 0
    var filter = if (arguments.has("filter")) arguments.get("filter").getAsString() else null
    var order = if (arguments.has("order")) arguments.get("order").getAsString() else "id desc"

    // Validate parameters
    if (limit < 1 || limit > 1000) {
      throw Exception("Limit must be between 1 and 1000")
    }
    if (offset < 0) {
      throw Exception("Offset must be non-negative")
    }

    try {
      var packets = Packets.getInstance()
      var allPackets = packets.queryAll()
      var filteredPackets = allPackets

      // Apply filter if provided
      if (filter != null && !filter.trim().isEmpty()) {
        filteredPackets = applyFilter(allPackets, filter)
      }

      // Apply ordering
      filteredPackets = applyOrdering(filteredPackets, order)

      var packetsArray = JsonArray()

      var totalCount = filteredPackets.size
      var startIndex = minOf(offset, totalCount)
      var endIndex = minOf(startIndex + limit, totalCount)

      for (i in startIndex until endIndex) {
        var packet = filteredPackets[i]
        var packetJson = convertPacketToJson(packet)
        packetsArray.add(packetJson)
      }

      var data = JsonObject()
      data.add("packets", packetsArray)
      data.addProperty("total_count", totalCount)
      data.addProperty("has_more", endIndex < totalCount)
      if (filter != null && !filter.trim().isEmpty()) {
        data.addProperty("filter_applied", filter)
      }
      data.addProperty("order_applied", order)

      var content = JsonObject()
      content.addProperty("type", "text")
      content.addProperty("text", gson.toJson(data))

      var contentArray = JsonArray()
      contentArray.add(content)

      var result = JsonObject()
      result.add("content", contentArray)

      log(
        "HistoryTool returning " +
          packetsArray.size() +
          " packets (filtered from " +
          allPackets.size +
          " total)"
      )
      return result
    } catch (e: Exception) {
      log("HistoryTool error: " + e.message)
      throw Exception("Failed to get packet history: " + e.message)
    }
  }

  @Throws(Exception::class)
  private fun applyFilter(packets: List<Packet>, filterText: String): List<Packet> {
    var filtered = ArrayList<Packet>()

    try {
      // Parse the filter using FilterTextParser
      var rowFilter = FilterTextParser.parse(filterText)

      for (packet in packets) {
        // Create a mock table entry to test the filter
        var rowData = createRowDataFromPacket(packet)
        var entry = MockTableEntry(rowData)

        if (rowFilter.include(entry)) {
          filtered.add(packet)
        }
      }
    } catch (e: Exception) {
      log("Filter parsing error: " + e.message)
      throw Exception("Invalid filter syntax: " + e.message)
    }

    return filtered
  }

  @Throws(Exception::class)
  private fun applyOrdering(packets: List<Packet>, orderString: String?): List<Packet> {
    if (orderString == null || orderString.trim().isEmpty()) {
      return packets
    }

    var parts = orderString.trim().split("\\s+".toRegex())
    if (parts.size != 2) {
      throw Exception("Invalid order format. Expected 'column asc|desc', got: $orderString")
    }

    var column = parts[0].lowercase()
    var direction = parts[1].lowercase()

    if (direction != "asc" && direction != "desc") {
      throw Exception("Invalid order direction. Expected 'asc' or 'desc', got: $direction")
    }

    var ascending = direction == "asc"
    var sortedPackets = ArrayList(packets)

    var comparator = getComparatorForColumn(column)
    if (comparator == null) {
      throw Exception("Invalid order column: $column")
    }

    if (!ascending) {
      comparator = comparator.reversed()
    }

    sortedPackets.sortWith(comparator)
    return sortedPackets
  }

  private fun getComparatorForColumn(column: String): Comparator<Packet>? =
    when (column) {
      "id" -> compareBy { it.getId() }
      "length" -> compareBy { it.getDecodedData().size }
      "client_ip" -> compareBy(nullsLast()) { it.getClientIP() }
      "client_port" -> compareBy { it.getClientPort() }
      "server_ip" -> compareBy(nullsLast()) { it.getServerIP() }
      "server_port" -> compareBy { it.getServerPort() }
      "time" -> compareBy(nullsLast()) { it.getDate() }
      "resend" -> compareBy { it.getResend() }
      "modified" -> compareBy { it.getModified() }
      "type" -> compareBy(nullsLast()) { it.getContentType() }
      "encode" -> compareBy(nullsLast()) { it.getEncoder() }
      "group" -> compareBy { it.getGroup() }
      "method" -> compareBy(nullsLast()) { extractMethod(it) }
      "url" -> compareBy(nullsLast()) { extractUrl(it) }
      "status" -> compareBy(nullsLast()) { extractStatus(it) }
      else -> null
    }

  private fun extractMethod(packet: Packet): String? {
    try {
      var request = String(packet.getDecodedData(), Charsets.UTF_8)
      var lines = request.split("\n")
      if (lines.isNotEmpty()) {
        var requestLine = lines[0].split(" ")
        if (requestLine.isNotEmpty()) {
          return requestLine[0]
        }
      }
    } catch (e: Exception) {
      // Ignore
    }
    return null
  }

  private fun extractUrl(packet: Packet): String? {
    try {
      var request = String(packet.getDecodedData(), Charsets.UTF_8)
      var lines = request.split("\n")
      if (lines.isNotEmpty()) {
        var requestLine = lines[0].split(" ")
        if (requestLine.size >= 2) {
          return requestLine[1]
        }
      }
    } catch (e: Exception) {
      // Ignore
    }
    return null
  }

  private fun extractStatus(packet: Packet): Int? {
    try {
      var request = String(packet.getDecodedData(), Charsets.UTF_8)
      var lines = request.split("\n")
      if (lines.isNotEmpty()) {
        var requestLine = lines[0].split(" ")
        if (requestLine.size >= 3 && requestLine[0].startsWith("HTTP/")) {
          return requestLine[1].toInt()
        }
      }
    } catch (e: Exception) {
      // Ignore
    }
    return null
  }

  private fun createRowDataFromPacket(packet: Packet): Array<Any?> {
    var rowData = arrayOfNulls<Any>(17) // Based on columnMapper size

    rowData[0] = packet.getId() // id

    // Extract request and response data
    try {
      var request = String(packet.getDecodedData(), Charsets.UTF_8)
      rowData[1] = request // request
      rowData[2] = "" // response (not available in current packet data)
    } catch (e: Exception) {
      rowData[1] = ""
      rowData[2] = ""
    }

    rowData[3] = packet.getDecodedData().size // length
    rowData[4] = packet.getClientIP() // client_ip
    rowData[5] = packet.getClientPort() // client_port
    rowData[6] = packet.getServerIP() // server_ip
    rowData[7] = packet.getServerPort() // server_port
    rowData[8] = packet.getDate() // time
    rowData[9] = packet.getResend() // resend
    rowData[10] = packet.getModified() // modified
    rowData[11] = packet.getContentType() // type
    rowData[12] = packet.getEncoder() // encode
    rowData[13] = "" // alpn (not available)
    rowData[14] = packet.getGroup() // group
    rowData[15] = rowData[1] as String // full_text (same as request)
    rowData[16] = (rowData[1] as String).lowercase() // full_text_i (lowercase)

    return rowData
  }

  // Mock table entry class for filter testing
  private class MockTableEntry(private val data: Array<Any?>) : RowFilter.Entry<Any, Any>() {
    override fun getModel(): Any? = null

    override fun getValueCount(): Int = data.size

    override fun getValue(index: Int): Any? = if (index < data.size) data[index] else null

    override fun getStringValue(index: Int): String {
      var value = getValue(index)
      return value?.toString() ?: ""
    }

    override fun getIdentifier(): Any? = null
  }

  private fun convertPacketToJson(packet: Packet): JsonObject {
    var packetJson = JsonObject()

    packetJson.addProperty("id", packet.getId())
    packetJson.addProperty("length", packet.getDecodedData().size)
    packetJson.addProperty("client_ip", packet.getClientIP())
    packetJson.addProperty("client_port", packet.getClientPort())
    packetJson.addProperty("server_ip", packet.getServerIP())
    packetJson.addProperty("server_port", packet.getServerPort())
    packetJson.addProperty("time", dateFormat.format(packet.getDate()))
    packetJson.addProperty("resend", packet.getResend())
    packetJson.addProperty("modified", packet.getModified())
    packetJson.addProperty("type", packet.getContentType())
    packetJson.addProperty("encode", packet.getEncoder())
    packetJson.addProperty("group", packet.getGroup())

    // HTTPの場合、methodとurlとstatusを抽出
    try {
      var request = String(packet.getDecodedData(), Charsets.UTF_8)
      var lines = request.split("\n")
      if (lines.isNotEmpty()) {
        var requestLine = lines[0].split(" ")
        if (requestLine.size >= 2) {
          packetJson.addProperty("method", requestLine[0])
          packetJson.addProperty("url", requestLine[1])
        }

        // レスポンスの場合、ステータスコードを抽出
        if (requestLine.size >= 3 && requestLine[0].startsWith("HTTP/")) {
          try {
            var status = requestLine[1].toInt()
            packetJson.addProperty("status", status)
          } catch (e: NumberFormatException) {
            // ステータスコードが数値でない場合は無視
          }
        }
      }
    } catch (e: Exception) {
      // HTTP以外のパケットの場合は無視
    }

    return packetJson
  }
}
