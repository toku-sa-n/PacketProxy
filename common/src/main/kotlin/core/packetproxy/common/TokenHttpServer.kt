package packetproxy.common

import com.google.gson.Gson
import fi.iki.elonen.NanoHTTPD
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.function.Consumer

class TokenHttpServer(hostname: String, port: Int, private val onReceived: Consumer<String>) :
  NanoHTTPD(hostname, port) {
  private var basicAuthUser: String? = null
  private var basicAuthPassword: String? = null

  constructor(
    hostname: String,
    port: Int,
    basicAuthUser: String?,
    basicAuthPassword: String?,
    onReceived: Consumer<String>,
  ) : this(hostname, port, onReceived) {
    this.basicAuthUser = basicAuthUser
    this.basicAuthPassword = basicAuthPassword
  }

  override fun serve(session: IHTTPSession): Response {
    if (session.method == Method.OPTIONS && session.uri == "/token") {
      return newFixedLengthResponse(Response.Status.OK, MIME_HTML, null).apply {
        addHeader("Access-Control-Allow-Origin", "*")
        addHeader("Access-Control-Allow-Headers", "Content-Type,Authorization")
        addHeader("Access-Control-Allow-Methods", "POST,OPTIONS")
        addHeader("Access-Control-Max-Age", "86400")
        addHeader("Access-Control-Allow-Private-Network", "true")
      }
    }
    if (session.method != Method.POST || session.uri != "/token") {
      return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_HTML, null)
    }
    if (!isAuthorized(session)) {
      return newFixedLengthResponse(Response.Status.UNAUTHORIZED, MIME_HTML, null).apply {
        addHeader("WWW-Authenticate", "Basic realm=\"PacketProxy\"")
      }
    }
    return try {
      val map = HashMap<String, String>()
      session.parseBody(map)
      val token = Gson().fromJson(map["postData"], Token::class.java)
      onReceived.accept(token.token)
      newFixedLengthResponse(Response.Status.OK, "application/json", "{\"status\": \"ok\"}").apply {
        addHeader("Access-Control-Allow-Origin", "*")
      }
    } catch (_: Exception) {
      newFixedLengthResponse(Response.Status.INTERNAL_ERROR, MIME_HTML, null)
    }
  }

  private fun isAuthorized(session: IHTTPSession): Boolean {
    val remote = session.remoteIpAddress
    val isLocalhost =
      remote == "127.0.0.1" ||
        remote == "::1" ||
        remote == "0:0:0:0:0:0:0:1" ||
        remote.equals("localhost", ignoreCase = true)
    if (isLocalhost) return true

    val user = basicAuthUser
    val pass = basicAuthPassword
    if (user.isNullOrEmpty() || pass.isNullOrEmpty()) {
      return false
    }
    val auth = session.headers["authorization"] ?: return false
    if (!auth.startsWith("Basic ", ignoreCase = true)) return false
    return try {
      val decoded =
        String(Base64.getDecoder().decode(auth.substring(6).trim()), StandardCharsets.UTF_8)
      val parts = decoded.split(":", limit = 2)
      parts.size == 2 && parts[0] == user && parts[1] == pass
    } catch (_: Exception) {
      false
    }
  }

  private class Token {
    lateinit var token: String
  }
}
