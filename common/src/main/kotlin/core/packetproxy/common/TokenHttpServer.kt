package packetproxy.common

import com.google.gson.Gson
import fi.iki.elonen.NanoHTTPD
import java.util.function.Consumer

class TokenHttpServer(hostname: String, port: Int, private val onReceived: Consumer<String>) :
  NanoHTTPD(hostname, port) {
  override fun serve(session: IHTTPSession): Response {
    if (session.method == Method.OPTIONS && session.uri == "/token") {
      return newFixedLengthResponse(Response.Status.OK, MIME_HTML, null).apply {
        addHeader("Access-Control-Allow-Origin", "*")
        addHeader("Access-Control-Allow-Headers", "Content-Type")
        addHeader("Access-Control-Allow-Methods", "POST,OPTIONS")
        addHeader("Access-Control-Max-Age", "86400")
        addHeader("Access-Control-Allow-Private-Network", "true")
      }
    }
    if (session.method != Method.POST || session.uri != "/token") {
      return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_HTML, null)
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

  private class Token {
    lateinit var token: String
  }
}
