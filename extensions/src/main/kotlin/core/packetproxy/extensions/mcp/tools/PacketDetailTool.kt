package packetproxy.extensions.mcp.tools

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import packetproxy.model.Configs
import packetproxy.model.Packet
import packetproxy.model.Packets
import packetproxy.util.log

class PacketDetailTool(private val packets: Packets, configs: Configs) :
  AuthenticatedMCPTool(configs) {

  private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
  private val gson = Gson()

  override fun getName(): String = "get_packet_detail"

  override fun getDescription(): String = "Get detailed information about a specific packet"

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var packetIdProp = JsonObject()
    packetIdProp.addProperty("type", "integer")
    packetIdProp.addProperty("description", "ID of the packet to retrieve")
    schema.add("packet_id", packetIdProp)

    var includeBodyProp = JsonObject()
    includeBodyProp.addProperty("type", "boolean")
    includeBodyProp.addProperty("description", "Whether to include request/response body")
    includeBodyProp.addProperty("default", true)
    schema.add("include_body", includeBodyProp)

    var includePairProp = JsonObject()
    includePairProp.addProperty("type", "boolean")
    includePairProp.addProperty(
      "description",
      "Whether to include paired packet (request when response specified, response when request specified)",
    )
    includePairProp.addProperty("default", false)
    schema.add("include_pair", includePairProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("PacketDetailTool called with arguments: " + getSafeArgumentsString(arguments))

    if (!arguments.has("packet_id")) {
      throw Exception("packet_id is required")
    }

    var packetId = arguments.get("packet_id").getAsInt()
    var includeBody = !arguments.has("include_body") || arguments.get("include_body").getAsBoolean()
    var includePair = arguments.has("include_pair") && arguments.get("include_pair").getAsBoolean()

    try {
      var packet = packets.query(packetId)

      if (packet == null) {
        throw Exception("Packet not found: $packetId")
      }

      var data = buildPacketDetail(packet, includeBody, includePair)

      var content = JsonObject()
      content.addProperty("type", "text")
      content.addProperty("text", gson.toJson(data))

      var contentArray = JsonArray()
      contentArray.add(content)

      var result = JsonObject()
      result.add("content", contentArray)

      log("PacketDetailTool returning packet $packetId")
      return result
    } catch (e: Exception) {
      log("PacketDetailTool error: " + e.message)
      throw Exception("Failed to get packet detail: " + e.message)
    }
  }

  @Throws(Exception::class)
  private fun buildPacketDetail(
    packet: Packet,
    includeBody: Boolean,
    includePair: Boolean,
  ): JsonObject {
    var result = JsonObject()

    if (includePair) {
      // Try to find the paired packet (request/response)
      var pairedPacket = findPairedPacket(packet)

      if (pairedPacket != null) {
        // Build paired request/response structure
        var requestPacket =
          if (packet.getDirection() == Packet.Direction.CLIENT) packet else pairedPacket
        var responsePacket =
          if (packet.getDirection() == Packet.Direction.SERVER) packet else pairedPacket

        // Request details
        var request = buildSinglePacketDetail(requestPacket, includeBody, "request")
        result.add("request", request)

        // Response details
        var response = buildSinglePacketDetail(responsePacket, includeBody, "response")
        result.add("response", response)

        // Add pairing information
        result.addProperty("paired", true)
        result.addProperty("requested_packet_id", packet.getId())
        result.addProperty("group", packet.getGroup())
        result.addProperty("conn", packet.getConn())
      } else {
        // Single packet (no pair found)
        var singlePacket =
          buildSinglePacketDetail(
            packet,
            includeBody,
            if (packet.getDirection() == Packet.Direction.CLIENT) "request" else "response",
          )
        if (packet.getDirection() == Packet.Direction.CLIENT) {
          result.add("request", singlePacket)
          result.add("response", null)
        } else {
          result.add("request", null)
          result.add("response", singlePacket)
        }
        result.addProperty("paired", false)
        result.addProperty("requested_packet_id", packet.getId())
        result.addProperty("group", packet.getGroup())
        result.addProperty("conn", packet.getConn())
      }
    } else {
      // Return only the requested packet
      var singlePacket =
        buildSinglePacketDetail(
          packet,
          includeBody,
          if (packet.getDirection() == Packet.Direction.CLIENT) "request" else "response",
        )
      if (packet.getDirection() == Packet.Direction.CLIENT) {
        result.add("request", singlePacket)
        result.add("response", null)
      } else {
        result.add("request", null)
        result.add("response", singlePacket)
      }
      result.addProperty("paired", false)
      result.addProperty("requested_packet_id", packet.getId())
      result.addProperty("group", packet.getGroup())
      result.addProperty("conn", packet.getConn())
    }

    return result
  }

  @Throws(Exception::class)
  private fun findPairedPacket(packet: Packet): Packet? {
    // Look for a packet with same group and conn but opposite direction
    var targetDirection =
      if (packet.getDirection() == Packet.Direction.CLIENT) Packet.Direction.SERVER
      else Packet.Direction.CLIENT

    // Search through packets with same group
    // Note: This is a simple implementation. In a real system, you might want to
    // add specific query methods to Packets class for better performance
    var allPackets = packets.queryAll()
    for (p in allPackets) {
      if (
        p.getGroup() == packet.getGroup() &&
          p.getConn() == packet.getConn() &&
          p.getDirection() == targetDirection &&
          p.getId() != packet.getId()
      ) {
        return p
      }
    }
    return null
  }

  @Throws(Exception::class)
  private fun buildSinglePacketDetail(
    packet: Packet,
    includeBody: Boolean,
    type: String,
  ): JsonObject {
    var result = JsonObject()

    // Basic packet info
    result.addProperty("id", packet.getId())
    result.addProperty("length", packet.getDecodedData().size)
    result.addProperty("time", dateFormat.format(packet.getDate()))
    result.addProperty("resend", packet.getResend())
    result.addProperty("modified", packet.getModified())
    result.addProperty("type", packet.getContentType())
    result.addProperty("encode", packet.getEncoder())
    result.addProperty("direction", packet.getDirection().toString().lowercase())

    // Client/Server info
    var client = JsonObject()
    client.addProperty("ip", packet.getClientIP())
    client.addProperty("port", packet.getClientPort())
    result.add("client", client)

    var server = JsonObject()
    server.addProperty("ip", packet.getServerIP())
    server.addProperty("port", packet.getServerPort())
    result.add("server", server)

    // Parse HTTP data if possible
    try {
      var data = String(packet.getDecodedData(), StandardCharsets.UTF_8)
      parseHttpData(result, data, includeBody)
    } catch (e: Exception) {
      // Not HTTP or parsing failed, include raw data
      if (includeBody) {
        result.addProperty("raw_data", String(packet.getDecodedData(), StandardCharsets.UTF_8))
      }
    }

    return result
  }

  private fun parseHttpData(result: JsonObject, data: String, includeBody: Boolean) {
    var parts = data.split("\r\n\r\n".toRegex(), 2)
    if (parts.isEmpty()) return

    var headers = parts[0]
    var body = if (parts.size > 1) parts[1] else ""

    var lines = headers.split("\r\n".toRegex())
    if (lines.isEmpty()) return

    // Parse request/response line
    var firstLine = lines[0]
    if (firstLine.startsWith("HTTP/")) {
      // Response
      var statusParts = firstLine.split(" ".toRegex(), 3)
      if (statusParts.size >= 2) {
        try {
          var status = statusParts[1].toInt()
          result.addProperty("status", status)
          if (statusParts.size >= 3) {
            result.addProperty("status_text", statusParts[2])
          }
        } catch (e: NumberFormatException) {
          // Invalid status code
        }
      }
    } else {
      // Request
      var requestParts = firstLine.split(" ".toRegex(), 3)
      if (requestParts.size >= 2) {
        result.addProperty("method", requestParts[0])
        result.addProperty("url", requestParts[1])
        if (requestParts.size >= 3) {
          result.addProperty("version", requestParts[2])
        }
      }
    }

    // Parse headers
    var headersArray = JsonArray()
    for (i in 1 until lines.size) {
      var line = lines[i]
      var colonIndex = line.indexOf(':')
      if (colonIndex > 0) {
        var header = JsonObject()
        header.addProperty("name", line.substring(0, colonIndex).trim())
        header.addProperty("value", line.substring(colonIndex + 1).trim())
        headersArray.add(header)
      }
    }
    result.add("headers", headersArray)

    // Include body if requested
    if (includeBody && body.isNotEmpty()) {
      result.addProperty("body", body)
    }
  }
}
