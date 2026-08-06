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
import packetproxy.http1.Http1StreamingResponse
import packetproxy.http2.Http2StreamingResponse
import packetproxy.model.Packet
import packetproxy.model.Packets
import packetproxy.util.errWithStackTrace

open class EncodeHTTPStreamingResponse : Encoder {
  enum class HTTPVersion {
    HTTP1,
    HTTP2,
  }

  private var httpVersion: HTTPVersion
  private var http1StreamingResponse: Http1StreamingResponse? = null
  private var http2StreamingResponse: Http2StreamingResponse? = null

  constructor() : super("http/1.1") {
    httpVersion = HTTPVersion.HTTP1
  }

  @Throws(Exception::class)
  constructor(ALPN: String?) : super(ALPN) {
    httpVersion =
      when {
        ALPN == null -> HTTPVersion.HTTP1
        ALPN == "http/1.0" || ALPN == "http/1.1" -> HTTPVersion.HTTP1
        ALPN == "h2" || ALPN.startsWith("grpc") -> HTTPVersion.HTTP2
        else -> HTTPVersion.HTTP1
      }
  }

  /** Wire Packets/UniqueID after reflective construction (Encoder only takes ALPN). */
  fun attachStreamingHelpers(packets: Packets, uniqueId: UniqueID) {
    if (http1StreamingResponse != null && http2StreamingResponse != null) {
      return
    }
    http1StreamingResponse = Http1StreamingResponse(packets)
    http2StreamingResponse = Http2StreamingResponse(packets, uniqueId)
  }

  private fun requireHttp1(): Http1StreamingResponse =
    http1StreamingResponse
      ?: throw IllegalStateException("HTTP/1 streaming helpers are not initialized")

  private fun requireHttp2(): Http2StreamingResponse =
    http2StreamingResponse
      ?: throw IllegalStateException("HTTP/2 streaming helpers are not initialized")

  fun getHttpVersion(): HTTPVersion = httpVersion

  // HTTP/2側はhttp2StreamingResponse独自のストリーム多重化・ウィンドウ管理を使うため専用スレッドが必要。
  override fun requiresDedicatedFlowControlThreads(): Boolean = httpVersion == HTTPVersion.HTTP2

  override fun getName(): String = "HTTP Streaming Response"

  @Throws(Exception::class)
  override fun checkRequestDelimiter(input_data: ByteArray): Int =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().checkRequestDelimiter(input_data)
    } else {
      requireHttp2().checkDelimiter(input_data)
    }

  @Throws(Exception::class)
  override fun checkResponseDelimiter(input_data: ByteArray): Int =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().checkResponseDelimiter(input_data)
    } else {
      requireHttp2().checkDelimiter(input_data)
    }

  @Throws(Exception::class)
  override fun clientRequestArrived(input_data: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().clientRequestArrived(input_data)
    } else {
      requireHttp2().clientRequestArrived(input_data)
    }
  }

  @Throws(Exception::class)
  override fun serverResponseArrived(input_data: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().serverResponseArrived(input_data)
    } else {
      requireHttp2().serverResponseArrived(input_data)
    }
  }

  @Throws(Exception::class)
  override fun passThroughClientRequest(): ByteArray? =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().passThroughClientRequest()
    } else {
      requireHttp2().passThroughClientRequest()
    }

  @Throws(Exception::class)
  override fun passThroughServerResponse(): ByteArray? =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().passThroughServerResponse()
    } else {
      requireHttp2().passThroughServerResponse()
    }

  @Throws(Exception::class)
  override fun clientRequestAvailable(): ByteArray? =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().clientRequestAvailable()
    } else {
      requireHttp2().clientRequestAvailable()
    }

  @Throws(Exception::class)
  override fun serverResponseAvailable(): ByteArray? =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().serverResponseAvailable()
    } else {
      requireHttp2().serverResponseAvailable()
    }

  @Throws(Exception::class)
  override fun decodeServerResponse(input_data: ByteArray): ByteArray =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().decodeServerResponse(input_data)
    } else {
      requireHttp2().decodeServerResponse(input_data)
    }

  @Throws(Exception::class)
  override fun encodeServerResponse(input_data: ByteArray): ByteArray =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().encodeServerResponse(input_data) ?: input_data
    } else {
      requireHttp2().encodeServerResponse(input_data) ?: input_data
    }

  @Throws(Exception::class)
  override fun decodeClientRequest(input_data: ByteArray): ByteArray =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().decodeClientRequest(input_data)
    } else {
      requireHttp2().decodeClientRequest(input_data)
    }

  @Throws(Exception::class)
  override fun encodeClientRequest(input_data: ByteArray): ByteArray =
    if (httpVersion == HTTPVersion.HTTP1) {
      requireHttp1().encodeClientRequest(input_data)
    } else {
      requireHttp2().encodeClientRequest(input_data)
    }

  @Throws(Exception::class)
  override fun putToClientFlowControlledQueue(output_data: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP1) {
      super.putToClientFlowControlledQueue(output_data)
    } else {
      requireHttp2().putToClientFlowControlledQueue(output_data)
    }
  }

  @Throws(Exception::class)
  override fun putToServerFlowControlledQueue(output_data: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP1) {
      super.putToServerFlowControlledQueue(output_data)
    } else {
      requireHttp2().putToServerFlowControlledQueue(output_data)
    }
  }

  override fun getClientFlowControlledInputStream(): InputStream =
    if (httpVersion == HTTPVersion.HTTP1) {
      super.getClientFlowControlledInputStream()
    } else {
      requireHttp2().getClientFlowControlledInputStream()
    }

  override fun getServerFlowControlledInputStream(): InputStream =
    if (httpVersion == HTTPVersion.HTTP1) {
      super.getServerFlowControlledInputStream()
    } else {
      requireHttp2().getServerFlowControlledInputStream()
    }

  @Throws(Exception::class)
  override fun getContentType(input_data: ByteArray): String {
    val http = Http.create(input_data)
    return http.getFirstHeader("Content-Type")
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
    if (httpVersion == HTTPVersion.HTTP1) {
      super.setGroupId(packet)
    } else {
      requireHttp2().setGroupId(packet)
    }
  }

  @Throws(Exception::class)
  override fun checkDelimiter(input_data: ByteArray): Int = input_data.size
}
