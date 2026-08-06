/*
 * Copyright 2019,2023 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.encode

import java.nio.charset.StandardCharsets
import java.util.Arrays
import packetproxy.http.Http
import packetproxy.websocket.WebSocket
import packetproxy.websocket.WebSocketFrame

open class EncodeHTTPWebSocket : Encoder {
  /**
   * Set when [clientRequestAvailable] replaced a zero-length payload with
   * [EMPTY_PAYLOAD_PLACEHOLDER].
   */
  private var clientEmptyPayloadFlag = false

  /**
   * Set when [serverResponseAvailable] replaced a zero-length payload with
   * [EMPTY_PAYLOAD_PLACEHOLDER].
   */
  private var serverEmptyPayloadFlag = false

  @JvmField protected var binary_start = false
  @JvmField var clientWebSocket = WebSocket()
  @JvmField var serverWebSocket = WebSocket()

  @Throws(Exception::class) constructor(ALPN: String?) : super(ALPN)

  @Throws(Exception::class) constructor() : super()

  override fun useNewConnectionForResend(): Boolean = false

  override fun useNewEncoderForResend(): Boolean = false

  override fun getName(): String = "HTTP WebSocket"

  @Throws(Exception::class)
  override fun checkDelimiter(input_data: ByteArray): Int {
    return if (binary_start) {
      WebSocket.checkDelimiter(input_data)
    } else {
      Http.parseHttpDelimiter(input_data)
    }
  }

  @Throws(Exception::class)
  override fun clientRequestArrived(input_data: ByteArray) {
    if (binary_start) {
      clientWebSocket.frameArrived(input_data)
    } else {
      super.clientRequestArrived(input_data)
    }
  }

  @Throws(Exception::class)
  override fun serverResponseArrived(input_data: ByteArray) {
    if (binary_start) {
      serverWebSocket.frameArrived(input_data)
    } else {
      super.serverResponseArrived(input_data)
    }
  }

  @Throws(Exception::class)
  override fun passThroughClientRequest(): ByteArray? {
    return if (binary_start) {
      clientWebSocket.passThroughFrame()
    } else {
      super.passThroughClientRequest()
    }
  }

  @Throws(Exception::class)
  override fun passThroughServerResponse(): ByteArray? {
    return if (binary_start) {
      serverWebSocket.passThroughFrame()
    } else {
      super.passThroughServerResponse()
    }
  }

  @Throws(Exception::class)
  override fun clientRequestAvailable(): ByteArray? {
    if (binary_start) {
      val payload = clientWebSocket.frameAvailable()
      // Simplex treats byte[0] from clientRequestAvailable as "no more chunks" (same
      // as Encoder base).
      // Map empty WebSocket payload to the placeholder so the duplex pipeline runs
      // decode/intercept/send.
      if (payload != null && payload.isEmpty()) {
        clientEmptyPayloadFlag = true
        return EMPTY_PAYLOAD_PLACEHOLDER
      }
      return payload
    } else {
      return super.clientRequestAvailable()
    }
  }

  @Throws(Exception::class)
  override fun serverResponseAvailable(): ByteArray? {
    if (binary_start) {
      val payload = serverWebSocket.frameAvailable()
      if (payload != null && payload.isEmpty()) {
        serverEmptyPayloadFlag = true
        return EMPTY_PAYLOAD_PLACEHOLDER
      }
      return payload
    } else {
      return super.serverResponseAvailable()
    }
  }

  @Throws(Exception::class)
  override fun decodeServerResponse(input_data: ByteArray): ByteArray {
    if (binary_start) {
      if (input_data.isEmpty()) {
        return EMPTY_PAYLOAD_PLACEHOLDER
      }
      return decodeWebsocketResponse(input_data)
    } else {
      val http = Http.create(input_data)
      return http.toByteArray()
    }
  }

  @Throws(Exception::class)
  override fun encodeServerResponse(input_data: ByteArray): ByteArray {
    if (binary_start) {
      val payload: ByteArray =
        if (serverEmptyPayloadFlag) {
          serverEmptyPayloadFlag = false
          if (Arrays.equals(input_data, EMPTY_PAYLOAD_PLACEHOLDER)) ByteArray(0)
          else encodeWebsocketResponse(input_data)
        } else {
          encodeWebsocketResponse(input_data)
        }
      val frame = WebSocketFrame.of(serverWebSocket.lastDequeuedOpCode(), payload, false)
      return frame.getBytes()
    } else {
      val http = Http.create(input_data)
      // encodeでやらないと、Switching Protocolsのレスポンス自体がwebsocketとしてencodeされてしまう
      binary_start = http.statusCode.matches(Regex("101"))
      return http.toByteArray()
    }
  }

  @Throws(Exception::class)
  override fun decodeClientRequest(input_data: ByteArray): ByteArray {
    if (binary_start) {
      if (input_data.isEmpty()) {
        return EMPTY_PAYLOAD_PLACEHOLDER
      }
      return decodeWebsocketRequest(input_data)
    } else {
      val http = Http.create(input_data)
      return http.toByteArray()
    }
  }

  @Throws(Exception::class)
  override fun encodeClientRequest(input_data: ByteArray): ByteArray {
    if (binary_start) {
      val payload: ByteArray =
        if (clientEmptyPayloadFlag) {
          clientEmptyPayloadFlag = false
          if (Arrays.equals(input_data, EMPTY_PAYLOAD_PLACEHOLDER)) ByteArray(0)
          else encodeWebsocketRequest(input_data)
        } else {
          encodeWebsocketRequest(input_data)
        }
      val frame = WebSocketFrame.of(clientWebSocket.lastDequeuedOpCode(), payload, true)
      return frame.getBytes()
    } else {
      val http = Http.create(input_data)
      return http.toByteArray()
    }
  }

  @Throws(Exception::class)
  override fun getContentType(input_data: ByteArray): String {
    return if (binary_start) {
      "WebSocket"
    } else {
      val http = Http.create(input_data)
      http.getFirstHeader("Content-Type")
    }
  }

  @Throws(Exception::class)
  open fun decodeWebsocketRequest(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class)
  open fun encodeWebsocketRequest(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class)
  open fun decodeWebsocketResponse(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class)
  open fun encodeWebsocketResponse(input_data: ByteArray): ByteArray = input_data

  companion object {
    /**
     * Sentinel shown in History/Intercept for empty-payload WebSocket frames. Encode path restores
     * this to a zero-length payload so the wire frame stays spec-compliant. If the user replaces
     * this text in Intercept, the edited bytes are sent as the actual payload.
     */
    @JvmField
    val EMPTY_PAYLOAD_PLACEHOLDER = "(empty WebSocket frame)".toByteArray(StandardCharsets.UTF_8)
  }
}
