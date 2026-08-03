package packetproxy.extensions.mcp.tools

import com.google.gson.JsonObject
import packetproxy.model.Modification
import packetproxy.model.Server
import packetproxy.model.Servers

internal object ModificationMcpHelpers {

  @Throws(Exception::class)
  fun toJson(modification: Modification, servers: Servers): JsonObject {
    var obj = JsonObject()
    obj.addProperty("id", modification.getId())
    obj.addProperty("enabled", modification.isEnabled())
    obj.addProperty("method", modification.getMethod()?.name)
    obj.addProperty("pattern", modification.getPattern())
    obj.addProperty("replaced", modification.getReplaced())
    obj.addProperty("direction", modification.getDirection()?.name)
    obj.addProperty("server_id", modification.getServerId())
    obj.addProperty("server", resolveServerName(modification.getServerId(), servers))
    return obj
  }

  @Throws(Exception::class)
  fun resolveServer(servers: Servers, serverStr: String): Server? {
    if (serverStr == "*") {
      return null
    }
    return servers.queryByString(serverStr)
      ?: throw IllegalArgumentException(
        "Unknown server: $serverStr. Use \"*\" for all servers, or a server display name from the Servers list."
      )
  }

  @Throws(Exception::class)
  fun parseMethod(value: String): Modification.Method {
    try {
      return Modification.Method.valueOf(value)
    } catch (_: IllegalArgumentException) {
      throw IllegalArgumentException(
        "Invalid method: $value. Must be one of: SIMPLE, REGEX, BINARY"
      )
    }
  }

  @Throws(Exception::class)
  fun parseDirection(value: String): Modification.Direction {
    try {
      return Modification.Direction.valueOf(value)
    } catch (_: IllegalArgumentException) {
      throw IllegalArgumentException(
        "Invalid direction: $value. Must be one of: CLIENT_REQUEST, SERVER_RESPONSE, ALL"
      )
    }
  }

  @Throws(Exception::class)
  private fun resolveServerName(serverId: Int, servers: Servers): String {
    if (serverId == Modification.ALL_SERVER) {
      return "*"
    }
    var server = servers.query(serverId)
    return server?.toString() ?: ""
  }
}
