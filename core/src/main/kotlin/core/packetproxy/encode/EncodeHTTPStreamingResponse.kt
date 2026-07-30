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
import packetproxy.http.Http
import packetproxy.http1.Http1StreamingResponse
import packetproxy.http2.Http2StreamingResponse
import packetproxy.model.Packet
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

  fun getHttpVersion(): HTTPVersion = httpVersion

  // HTTP/2側はhttp2StreamingResponse独自のストリーム多重化・ウィンドウ管理を使うため専用スレッドが必要。
  override fun requiresDedicatedFlowControlThreads(): Boolean = httpVersion == HTTPVersion.HTTP2

  override fun getName(): String = "HTTP Streaming Response"

  @Throws(Exception::class)
  override fun checkRequestDelimiter(data: ByteArray): Int =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.checkRequestDelimiter(data)
    } else {
      http2StreamingResponse!!.checkDelimiter(data)
    }

  @Throws(Exception::class)
  override fun checkResponseDelimiter(data: ByteArray): Int =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.checkResponseDelimiter(data)
    } else {
      http2StreamingResponse!!.checkDelimiter(data)
    }

  @Throws(Exception::class)
  override fun clientRequestArrived(data: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.clientRequestArrived(data)
    } else {
      http2StreamingResponse!!.clientRequestArrived(data)
    }
  }

  @Throws(Exception::class)
  override fun serverResponseArrived(data: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.serverResponseArrived(data)
    } else {
      http2StreamingResponse!!.serverResponseArrived(data)
    }
  }

  @Throws(Exception::class)
  override fun passThroughClientRequest(): ByteArray? =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.passThroughClientRequest()
    } else {
      http2StreamingResponse!!.passThroughClientRequest()
    }

  @Throws(Exception::class)
  override fun passThroughServerResponse(): ByteArray? =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.passThroughServerResponse()
    } else {
      http2StreamingResponse!!.passThroughServerResponse()
    }

  @Throws(Exception::class)
  override fun clientRequestAvailable(): ByteArray? =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.clientRequestAvailable()
    } else {
      http2StreamingResponse!!.clientRequestAvailable()
    }

  @Throws(Exception::class)
  override fun serverResponseAvailable(): ByteArray? =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.serverResponseAvailable()
    } else {
      http2StreamingResponse!!.serverResponseAvailable()
    }

  @Throws(Exception::class)
  override fun decodeServerResponse(input_data: ByteArray): ByteArray =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.decodeServerResponse(input_data)
    } else {
      http2StreamingResponse!!.decodeServerResponse(input_data)
    }

  @Throws(Exception::class)
  override fun encodeServerResponse(input_data: ByteArray): ByteArray =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.encodeServerResponse(input_data) ?: input_data
    } else {
      http2StreamingResponse!!.encodeServerResponse(input_data) ?: input_data
    }

  @Throws(Exception::class)
  override fun decodeClientRequest(input_data: ByteArray): ByteArray =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.decodeClientRequest(input_data)
    } else {
      http2StreamingResponse!!.decodeClientRequest(input_data)
    }

  @Throws(Exception::class)
  override fun encodeClientRequest(input_data: ByteArray): ByteArray =
    if (httpVersion == HTTPVersion.HTTP1) {
      http1StreamingResponse!!.encodeClientRequest(input_data)
    } else {
      http2StreamingResponse!!.encodeClientRequest(input_data)
    }

  @Throws(Exception::class)
  override fun putToClientFlowControlledQueue(frames: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP1) {
      super.putToClientFlowControlledQueue(frames)
    } else {
      http2StreamingResponse!!.putToClientFlowControlledQueue(frames)
    }
  }

  @Throws(Exception::class)
  override fun putToServerFlowControlledQueue(frames: ByteArray) {
    if (httpVersion == HTTPVersion.HTTP1) {
      super.putToServerFlowControlledQueue(frames)
    } else {
      http2StreamingResponse!!.putToServerFlowControlledQueue(frames)
    }
  }

  override fun getClientFlowControlledInputStream(): InputStream =
    if (httpVersion == HTTPVersion.HTTP1) {
      super.getClientFlowControlledInputStream()
    } else {
      http2StreamingResponse!!.getClientFlowControlledInputStream()
    }

  override fun getServerFlowControlledInputStream(): InputStream =
    if (httpVersion == HTTPVersion.HTTP1) {
      super.getServerFlowControlledInputStream()
    } else {
      http2StreamingResponse!!.getServerFlowControlledInputStream()
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
      http2StreamingResponse!!.setGroupId(packet)
    }
  }

  @Throws(Exception::class)
  override fun checkDelimiter(input_data: ByteArray): Int = input_data.size
}
