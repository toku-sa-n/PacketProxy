/*
 * Copyright 2019 DeNA Co., Ltd.
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

import java.io.InputStream
import packetproxy.common.UniqueID
import packetproxy.http.Http
import packetproxy.http2.FramesBase
import packetproxy.http2.Http2
import packetproxy.http3.service.Http3
import packetproxy.model.Packet
import packetproxy.util.errWithStackTrace

abstract class EncodeHTTPBase : Encoder {
  enum class HTTPVersion {
    HTTP1,
    HTTP2,
    HTTP3,
  }

  private var httpVersion: HTTPVersion
  private var http2: FramesBase? = null
  private var http3: Http3? = null
  private var requestMethod: String = ""

  constructor() : super("http/1.1") {
    httpVersion = HTTPVersion.HTTP1
  }

  @Throws(Exception::class)
  constructor(ALPN: String?) : super(ALPN) {
    httpVersion =
      when {
        ALPN == null -> HTTPVersion.HTTP1
        ALPN == "http/1.0" || ALPN == "http/1.1" -> HTTPVersion.HTTP1
        ALPN == "h2" || ALPN == "grpc" || ALPN == "grpc-exp" -> {
          http2 = Http2(UniqueID())
          HTTPVersion.HTTP2
        }
        ALPN == "h3" -> {
          http3 = Http3(UniqueID())
          HTTPVersion.HTTP3
        }
        else -> HTTPVersion.HTTP1
      }
  }

  @Throws(Exception::class)
  constructor(ALPN: String?, http2CustomFrame: FramesBase) : super(ALPN) {
    httpVersion = HTTPVersion.HTTP2
    this.http2 = http2CustomFrame
  }

  fun getHttpVersion(): HTTPVersion = httpVersion

  @Throws(Exception::class)
  override fun checkDelimiter(data: ByteArray): Int =
    when (httpVersion) {
      HTTPVersion.HTTP1 -> Http.parseHttpDelimiter(data)
      HTTPVersion.HTTP2 -> http2!!.checkDelimiter(data)
      else -> http3!!.checkDelimiter(data)
    }

  @Throws(Exception::class)
  override fun checkResponseDelimiter(data: ByteArray): Int {
    if (requestMethod == "HEAD") return data.size
    return checkDelimiter(data)
  }

  @Throws(Exception::class)
  override fun clientRequestArrived(frames: ByteArray) {
    when (httpVersion) {
      HTTPVersion.HTTP1 -> super.clientRequestArrived(frames)
      HTTPVersion.HTTP2 -> http2!!.clientRequestArrived(frames)
      else -> http3!!.clientRequestArrived(frames)
    }
  }

  @Throws(Exception::class)
  override fun serverResponseArrived(frames: ByteArray) {
    when (httpVersion) {
      HTTPVersion.HTTP1 -> super.serverResponseArrived(frames)
      HTTPVersion.HTTP2 -> http2!!.serverResponseArrived(frames)
      else -> http3!!.serverResponseArrived(frames)
    }
  }

  @Throws(Exception::class)
  override fun passThroughClientRequest(): ByteArray? =
    when (httpVersion) {
      HTTPVersion.HTTP1 -> super.passThroughClientRequest()
      HTTPVersion.HTTP2 -> http2!!.passThroughClientRequest()
      else -> http3!!.passThroughClientRequest()
    }

  @Throws(Exception::class)
  override fun passThroughServerResponse(): ByteArray? =
    when (httpVersion) {
      HTTPVersion.HTTP1 -> super.passThroughServerResponse()
      HTTPVersion.HTTP2 -> http2!!.passThroughServerResponse()
      else -> http3!!.passThroughServerResponse()
    }

  @Throws(Exception::class)
  override fun clientRequestAvailable(): ByteArray? =
    when (httpVersion) {
      HTTPVersion.HTTP1 -> super.clientRequestAvailable()
      HTTPVersion.HTTP2 -> http2!!.clientRequestAvailable()
      else -> http3!!.clientRequestAvailable()
    }

  @Throws(Exception::class)
  override fun serverResponseAvailable(): ByteArray? =
    when (httpVersion) {
      HTTPVersion.HTTP1 -> super.serverResponseAvailable()
      HTTPVersion.HTTP2 -> http2!!.serverResponseAvailable()
      else -> http3!!.serverResponseAvailable()
    }

  @Throws(Exception::class)
  override fun decodeClientRequest(input_data: ByteArray): ByteArray {
    var data = input_data
    if (httpVersion == HTTPVersion.HTTP2) {
      data = http2!!.decodeClientRequest(data)
    } else if (httpVersion == HTTPVersion.HTTP3) {
      data = http3!!.decodeClientRequest(data)
    }
    val http = Http.create(data)
    var decodedHttp = http
    if (http.getFirstHeader("X-PacketProxy-Skip-ClientSideEncode").contains("true")) {
      encode_mode = 1
    } else {
      decodedHttp = decodeClientRequestHttp(http)
    }
    return decodedHttp.toByteArray()
  }

  @Throws(Exception::class)
  override fun encodeClientRequest(input_data: ByteArray): ByteArray {
    val http = Http.create(input_data)
    requestMethod = http.method
    val encodedHttp = encodeClientRequestHttp(http)
    var encodedData = encodedHttp.toByteArray()
    if (httpVersion == HTTPVersion.HTTP2) {
      encodedData = http2!!.encodeClientRequest(encodedData)
    } else if (httpVersion == HTTPVersion.HTTP3) {
      encodedData = http3!!.encodeClientRequest(encodedData)
    }
    return encodedData
  }

  @Throws(Exception::class)
  override fun decodeServerResponse(input_data: ByteArray): ByteArray {
    var data = input_data
    if (httpVersion == HTTPVersion.HTTP2) {
      data = http2!!.decodeServerResponse(data)
    } else if (httpVersion == HTTPVersion.HTTP3) {
      data = http3!!.decodeServerResponse(data)
    }
    val http =
      if (requestMethod == "HEAD") {
        Http.createWithoutTouchingContentLength(data)
      } else {
        Http.create(data)
      }
    val decodedHttp = decodeServerResponseHttp(http)
    return decodedHttp.toByteArray()
  }

  @Throws(Exception::class)
  override fun encodeServerResponse(input_data: ByteArray): ByteArray {
    val http =
      if (requestMethod == "HEAD") {
        Http.createWithoutTouchingContentLength(input_data)
      } else {
        Http.create(input_data)
      }
    var encodedHttp = http
    if (encode_mode == 0) {
      encodedHttp = encodeServerResponseHttp(http)
    }
    var encodedData = encodedHttp.toByteArray()
    if (httpVersion == HTTPVersion.HTTP2) {
      encodedData = http2!!.encodeServerResponse(encodedData)
    } else if (httpVersion == HTTPVersion.HTTP3) {
      encodedData = http3!!.encodeServerResponse(encodedData)
    }
    return encodedData
  }

  @Throws(Exception::class)
  override fun putToClientFlowControlledQueue(frames: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP2) {
      http2!!.putToClientFlowControlledQueue(frames)
    } else {
      super.putToClientFlowControlledQueue(frames)
    }
  }

  @Throws(Exception::class)
  override fun putToServerFlowControlledQueue(frames: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP2) {
      http2!!.putToServerFlowControlledQueue(frames)
    } else {
      super.putToServerFlowControlledQueue(frames)
    }
  }

  override fun getClientFlowControlledInputStream(): InputStream =
    if (httpVersion == HTTPVersion.HTTP2) {
      http2!!.getClientFlowControlledInputStream()
    } else {
      super.getClientFlowControlledInputStream()
    }

  override fun getServerFlowControlledInputStream(): InputStream =
    if (httpVersion == HTTPVersion.HTTP2) {
      http2!!.getServerFlowControlledInputStream()
    } else {
      super.getServerFlowControlledInputStream()
    }

  @Throws(Exception::class)
  override fun getContentType(input_data: ByteArray): String {
    val http = Http.create(input_data)
    return http.getFirstHeader("Content-Type")
  }

  /**
   * レスポンスからContent-Typeを取得し、存在しない場合はリクエストのContent-Typeをフォールバックとして使用する。
   * gRPC等のプロトコルでは、レスポンスにContent-Typeが含まれないことがあるため、
   * リクエストのContent-Typeを使用することで、History一覧のType列に適切な値を表示する。
   */
  @Throws(Exception::class)
  override fun getContentType(client_packet: Packet?, server_packet: Packet): String {
    var contentType = getContentType(server_packet.getDecodedData())
    if (
      contentType.isEmpty() && client_packet != null && client_packet.getDecodedData().isNotEmpty()
    ) {
      contentType = getContentType(client_packet.getDecodedData())
    }
    return contentType
  }

  override fun getSummarizedResponse(packet: Packet): String {
    var summary = ""
    if (packet.getDecodedData().isEmpty() && packet.getModifiedData().isEmpty()) {
      return ""
    }
    try {
      val data =
        if (packet.getDecodedData().isNotEmpty()) packet.getDecodedData()
        else packet.getModifiedData()
      val http = Http.create(data)
      summary = http.statusCode
    } catch (e: Exception) {
      errWithStackTrace(e)
      summary = "Headlineを生成できません・・・"
    }
    return summary
  }

  override fun getSummarizedRequest(packet: Packet): String {
    var summary = ""
    if (packet.getDecodedData().isEmpty() && packet.getModifiedData().isEmpty()) {
      return ""
    }
    try {
      val data =
        if (packet.getDecodedData().isNotEmpty()) packet.getDecodedData()
        else packet.getModifiedData()
      val http = Http.create(data)
      summary = http.method + " " + http.getURL(packet.getServerPort(), packet.getUseSSL())
    } catch (e: Exception) {
      errWithStackTrace(e)
      summary = "Headlineを生成できません・・・"
    }
    return summary
  }

  @Throws(Exception::class)
  override fun setGroupId(packet: Packet) {
    when (httpVersion) {
      HTTPVersion.HTTP2 -> http2!!.setGroupId(packet)
      HTTPVersion.HTTP3 -> http3!!.setGroupId(packet)
      else -> super.setGroupId(packet)
    }
  }

  @Throws(Exception::class) protected abstract fun decodeServerResponseHttp(inputHttp: Http): Http

  @Throws(Exception::class) protected abstract fun encodeServerResponseHttp(inputHttp: Http): Http

  @Throws(Exception::class) protected abstract fun decodeClientRequestHttp(inputHttp: Http): Http

  @Throws(Exception::class) protected abstract fun encodeClientRequestHttp(inputHttp: Http): Http
}
