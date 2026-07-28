package packetproxy.extensions.mcp.tools

import com.google.gson.JsonObject
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import javax.swing.SwingUtilities
import packetproxy.common.StringUtils
import packetproxy.common.UniqueID
import packetproxy.gui.GUIResender
import packetproxy.model.Configs
import packetproxy.model.OneShotPacket
import packetproxy.model.Packet
import packetproxy.util.log

/**
 * Creates a Resender tab with an arbitrary HTTP/2 request (staging only, does not send). Mirrors
 * Burp MCP's create_repeater_tab_http2.
 */
class CreateResenderTabHttp2Tool(
  private val uniqueId: UniqueID,
  private val guiResender: GUIResender,
  configs: Configs,
) : AuthenticatedMCPTool(configs) {

  override fun getName(): String = "create_resender_tab_http2"

  override fun getDescription(): String =
    "Creates a Resender tab with the specified HTTP/2 request. Use this for HTTP/2 targets. " +
      "Do NOT pass headers in the request_body parameter. Staging only — does not send the request."

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var pseudoHeadersProp = JsonObject()
    pseudoHeadersProp.addProperty("type", "object")
    pseudoHeadersProp.addProperty(
      "description",
      "HTTP/2 pseudo-headers as a map. Keys may be with or without leading colon " +
        "(e.g. method or :method). Required keys: method, path. Optional: scheme, authority.",
    )
    schema.add("pseudo_headers", pseudoHeadersProp)

    var headersProp = JsonObject()
    headersProp.addProperty("type", "object")
    headersProp.addProperty("description", "Regular HTTP headers as a map of name to value")
    schema.add("headers", headersProp)

    var requestBodyProp = JsonObject()
    requestBodyProp.addProperty("type", "string")
    requestBodyProp.addProperty(
      "description",
      "Request body only. Do NOT pass headers here. Empty string is allowed.",
    )
    requestBodyProp.addProperty("default", "")
    schema.add("request_body", requestBodyProp)

    var targetHostnameProp = JsonObject()
    targetHostnameProp.addProperty("type", "string")
    targetHostnameProp.addProperty("description", "Target hostname (used for connection and SNI)")
    schema.add("target_hostname", targetHostnameProp)

    var targetPortProp = JsonObject()
    targetPortProp.addProperty("type", "integer")
    targetPortProp.addProperty("description", "Target port")
    schema.add("target_port", targetPortProp)

    var useSslProp = JsonObject()
    useSslProp.addProperty("type", "boolean")
    useSslProp.addProperty("description", "Whether to use TLS/SSL for the connection")
    schema.add("use_ssl", useSslProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("CreateResenderTabHttp2Tool called with arguments: " + getSafeArgumentsString(arguments))

    if (!arguments.has("pseudo_headers") || !arguments.get("pseudo_headers").isJsonObject) {
      throw IllegalArgumentException("pseudo_headers parameter is required and must be an object")
    }
    if (!arguments.has("headers") || !arguments.get("headers").isJsonObject) {
      throw IllegalArgumentException("headers parameter is required and must be an object")
    }
    if (!arguments.has("target_hostname")) {
      throw IllegalArgumentException("target_hostname parameter is required")
    }
    if (!arguments.has("target_port")) {
      throw IllegalArgumentException("target_port parameter is required")
    }
    if (!arguments.has("use_ssl")) {
      throw IllegalArgumentException("use_ssl parameter is required")
    }

    var targetHostname = arguments.get("target_hostname").asString
    var targetPort = arguments.get("target_port").asInt
    var useSsl = arguments.get("use_ssl").asBoolean
    var requestBody =
      if (arguments.has("request_body")) arguments.get("request_body").asString else ""

    var pseudoHeaders = normalizeHeaderMap(arguments.getAsJsonObject("pseudo_headers"))
    var headers = jsonObjectToMap(arguments.getAsJsonObject("headers"))

    var method =
      getPseudoHeader(pseudoHeaders, "method")
        ?: throw IllegalArgumentException("pseudo_headers.method (:method) is required")
    var path =
      getPseudoHeader(pseudoHeaders, "path")
        ?: throw IllegalArgumentException("pseudo_headers.path (:path) is required")
    var scheme =
      getPseudoHeader(pseudoHeaders, "scheme")
        ?: if (useSsl) {
          "https"
        } else {
          "http"
        }
    var authority = getPseudoHeader(pseudoHeaders, "authority") ?: targetHostname

    var serverAddr = InetSocketAddress(targetHostname, targetPort)
    if (serverAddr.address == null) {
      throw IllegalArgumentException("Cannot resolve target_hostname: $targetHostname")
    }

    var data = buildHttp2EditorBytes(method, path, scheme, authority, headers, requestBody)
    var oneShot =
      OneShotPacket(
        0,
        0,
        InetSocketAddress("127.0.0.1", 0),
        serverAddr,
        targetHostname,
        useSsl,
        data,
        "HTTP",
        "h2",
        Packet.Direction.CLIENT,
        0,
        uniqueId.createId(),
      )

    SwingUtilities.invokeAndWait { guiResender.addResends(oneShot) }

    var result = JsonObject()
    result.addProperty("success", true)
    result.addProperty("target_hostname", targetHostname)
    result.addProperty("target_port", targetPort)
    result.addProperty("use_ssl", useSsl)
    result.addProperty("alpn", "h2")
    result.addProperty("encoder", "HTTP")
    result.addProperty("method", method)
    result.addProperty("path", path)

    log(
      "CreateResenderTabHttp2Tool: Added HTTP/2 request to Resender " +
        "($method $path -> $targetHostname:$targetPort, use_ssl=$useSsl)"
    )
    return result
  }

  private fun buildHttp2EditorBytes(
    method: String,
    path: String,
    scheme: String,
    authority: String,
    headers: Map<String, String>,
    requestBody: String,
  ): ByteArray {
    var buf = StringBuilder()
    buf.append(method).append(' ').append(path).append(" HTTP/2\r\n")
    for ((name, value) in headers) {
      buf.append(name).append(": ").append(value).append("\r\n")
    }

    var flags =
      if (requestBody.isEmpty()) {
        FLAG_END_HEADERS or FLAG_END_STREAM
      } else {
        FLAG_END_HEADERS
      }

    buf.append("X-PacketProxy-HTTP2-Scheme: ").append(scheme).append("\r\n")
    buf.append("X-PacketProxy-HTTP2-Host: ").append(authority).append("\r\n")
    buf.append("X-PacketProxy-HTTP2-Type: ").append(HEADERS_TYPE).append("\r\n")
    buf.append("X-PacketProxy-HTTP2-Stream-Id: 1\r\n")
    buf.append("X-PacketProxy-HTTP2-Flags: ").append(flags).append("\r\n")
    buf.append("X-PacketProxy-HTTP2-UUID: ").append(StringUtils.randomUUID()).append("\r\n")
    buf.append("\r\n")
    buf.append(requestBody)
    return buf.toString().toByteArray(StandardCharsets.UTF_8)
  }

  private fun normalizeHeaderMap(obj: JsonObject): Map<String, String> {
    var normalized = LinkedHashMap<String, String>()
    for ((key, value) in jsonObjectToMap(obj)) {
      var properKey = if (key.startsWith(":")) key else ":$key"
      if (!normalized.containsKey(properKey)) {
        normalized[properKey] = value
      }
    }
    return normalized
  }

  private fun getPseudoHeader(pseudoHeaders: Map<String, String>, name: String): String? {
    var withColon = ":$name"
    return pseudoHeaders[withColon] ?: pseudoHeaders[name]
  }

  private fun jsonObjectToMap(obj: JsonObject): Map<String, String> {
    var map = LinkedHashMap<String, String>()
    for (entry in obj.entrySet()) {
      if (entry.value == null || entry.value.isJsonNull) {
        continue
      }
      map[entry.key] = entry.value.asString
    }
    return map
  }

  companion object {
    private val HEADERS_TYPE = 1
    private val FLAG_END_STREAM = 0x01
    private val FLAG_END_HEADERS = 0x04
  }
}
