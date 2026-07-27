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
package packetproxy.http2.frames

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import org.apache.commons.lang3.ArrayUtils
import org.eclipse.jetty.http.HttpFields
import org.eclipse.jetty.http.HttpStatus
import org.eclipse.jetty.http.HttpURI
import org.eclipse.jetty.http.HttpVersion
import org.eclipse.jetty.http.MetaData
import org.eclipse.jetty.http.MetaData.Request
import org.eclipse.jetty.http.MetaData.Response
import org.eclipse.jetty.http2.hpack.HpackDecoder
import org.eclipse.jetty.http2.hpack.HpackEncoder
import packetproxy.common.StringUtils
import packetproxy.http.Http
import packetproxy.http.HttpHeader

class HeadersFrame : Frame {
  private var method: String? = null
  private var path: String? = null
  private var scheme: String? = null
  private var authority: String? = null
  private var query: String? = null
  private var uriString: String? = null
  private var fields: HttpFields? = null
  private var bRequest = false
  private var bResponse = false
  private var bTrailer = false
  private var isGRPC2ndResponseHeader = false
  private var status = 0
  private var version: HttpVersion? = null
  private var priority = false
  private var dependency = 0
  private var weight = 0

  @Throws(Exception::class)
  constructor(frameData: ByteArray, decoder: HpackDecoder?) : super(frameData) {
    decodeToHttp(decoder)
  }

  @Throws(Exception::class)
  constructor(frame: Frame, decoder: HpackDecoder?) : super(frame) {
    decodeToHttp(decoder)
  }

  @Throws(Exception::class)
  constructor(http: Http) : super() {
    type = TYPE
    for (field in http.header.fields) {
      when (field.getName()) {
        "X-PacketProxy-HTTP2-Stream-Id" -> streamId = field.getValue().toInt()
        "X-PacketProxy-HTTP2-Flags" -> flags = flags or field.getValue().toInt()
        "X-PacketProxy-HTTP2-GRPC-2nd-Frame-Header" -> bTrailer = true
      }
    }
    saveExtra(http.toByteArray())
  }

  @Throws(Exception::class) fun getHttp(): ByteArray = getExtra()

  @Throws(Exception::class)
  fun toByteArrayWithoutExtra(encoder: HpackEncoder): ByteArray = toByteArrayWithoutExtra(encoder, false)

  @Throws(Exception::class)
  fun toByteArrayWithoutExtra(encoder: HpackEncoder, originalHttpHeader: Boolean): ByteArray =
    toByteArrayWithoutExtra(encoder, originalHttpHeader, true)

  @Throws(Exception::class)
  fun toByteArrayWithoutExtra(
    encoder: HpackEncoder,
    originalHttpHeader: Boolean,
    withContentLength: Boolean,
  ): ByteArray {
    encodeFromHttp(encoder, originalHttpHeader, withContentLength)
    return super.toByteArrayWithoutExtra()
  }

  @Throws(Exception::class)
  private fun encodeFromHttp(
    encoder: HpackEncoder,
    originalHttpHeader: Boolean,
    withContentLength: Boolean,
  ) {
    if ((flags and FLAG_EXTRA.toInt()) == 0) {
      return
    }
    val http = Http.create(getExtra())
    method = http.method
    version = HttpVersion.fromString("HTTP/2")
    val headers: HttpHeader = if (originalHttpHeader) http.getOriginalHeader() else http.header
    var mutableFields = HttpFields.build()
    for (field in headers.fields) {
      when {
        field.getName() == "X-PacketProxy-HTTP2-Scheme" -> scheme = field.getValue()
        field.getName() == "X-PacketProxy-HTTP2-Host" -> {
          authority = field.getValue()
          path = http.path
          query = http.getQueryAsString()
          val queryStr = if (!query.isNullOrEmpty()) "?$query" else ""
          uriString = "$scheme://$authority$path$queryStr"
        }
        field.getName() == "X-PacketProxy-HTTP2-Dependency" -> {
          priority = true
          dependency = field.getValue().toInt()
        }
        field.getName() == "X-PacketProxy-HTTP2-Weight" -> weight = field.getValue().toInt()
        !withContentLength && field.getName() == "content-length" -> {}
        !field.getName().startsWith("X-PacketProxy") -> mutableFields.add(field.getName(), field.getValue())
      }
    }
    fields = mutableFields

    val meta: MetaData =
      if (http.isRequest()) {
        val uri = HttpURI.build().uri(uriString)
        if (withContentLength) {
          var contentLength = 0L
          if (method == "GET" || method == "HEAD") {
            contentLength = if (http.body.isEmpty()) Long.MIN_VALUE else http.body.size.toLong()
          } else if (method == "POST" || method == "PUT") {
            contentLength = http.body.size.toLong()
            mutableFields.add("content-length", contentLength.toString())
            fields = mutableFields
          }
          MetaData.Request(method, uri, version, fields, contentLength)
        } else {
          MetaData.Request(method, uri, version, fields)
        }
      } else if (bTrailer) {
        MetaData(version, fields)
      } else {
        status = http.statusCode!!.toInt()
        val contentLength = if (http.body.isEmpty()) Long.MIN_VALUE else http.body.size.toLong()
        MetaData.Response(version, http.statusCode!!.toInt(), fields, contentLength)
      }

    val buffer = ByteBuffer.allocate(65535)
    encoder.encode(buffer, meta)
    var headersPayload = ByteArray(buffer.position())
    buffer.flip()
    buffer.get(headersPayload)
    if (priority) {
      val b = ByteBuffer.allocate(16)
      b.putInt(dependency or Integer.MIN_VALUE)
      b.put((weight and 0xff).toByte())
      val priorityField = ByteArray(b.position())
      b.flip()
      b.get(priorityField)
      headersPayload = ArrayUtils.addAll(priorityField, headersPayload)
    }
    saveOrigPayload(headersPayload)
  }

  @Throws(Exception::class)
  private fun decodeToHttp(decoder: HpackDecoder?) {
    if ((flags and FLAG_EXTRA.toInt()) > 0) return
    if (decoder == null) return
    val input = ByteBuffer.allocate(65535)
    input.put(payload)
    input.flip()
    if ((flags and FLAG_PRIORITY.toInt()) > 0) {
      priority = true
      dependency = input.getInt() and 0x7fffffff
      weight = input.get().toInt()
    }
    val meta = decoder.decode(input)
    isGRPC2ndResponseHeader = false
    if (meta is Request) {
      bRequest = true
      method = meta.method
      version = meta.httpVersion
      uriString = meta.getURIString()
      val uri = meta.uri
      scheme = uri.scheme
      authority = uri.authority
      path = uri.path
      query = uri.query
    } else if (meta is Response) {
      bResponse = true
      status = meta.status
    } else {
      bTrailer = true
    }
    fields = meta.fields
    if (bTrailer) {
      for (i in fields!!) {
        if (i.name.contains("grpc-status")) {
          isGRPC2ndResponseHeader = true
          break
        }
      }
    }
    val buf = ByteArrayOutputStream()
    if (bRequest) {
      val queryStr = if (!query.isNullOrEmpty()) "?$query" else ""
      buf.write(String.format("%s %s%s HTTP/2\r\n", method, path, queryStr).toByteArray())
    } else {
      buf.write(String.format("HTTP/2 %d %s\r\n", status, HttpStatus.getMessage(status)).toByteArray())
    }
    for (field in fields!!) {
      buf.write(String.format("%s: %s\r\n", field.name, field.value).toByteArray())
    }
    if (!isGRPC2ndResponseHeader) {
      if (bRequest) {
        buf.write(String.format("X-PacketProxy-HTTP2-Scheme: %s\r\n", scheme).toByteArray())
        buf.write(String.format("X-PacketProxy-HTTP2-Host: %s\r\n", authority).toByteArray())
      }
      if (priority) {
        buf.write(String.format("X-PacketProxy-HTTP2-Dependency: %d\r\n", dependency).toByteArray())
        buf.write(String.format("X-PacketProxy-HTTP2-Weight: %d\r\n", weight and 0xff).toByteArray())
      }
      buf.write(String.format("X-PacketProxy-HTTP2-Type: %d\r\n", TYPE.ordinal).toByteArray())
      buf.write(String.format("X-PacketProxy-HTTP2-Stream-Id: %d\r\n", streamId).toByteArray())
      buf.write(String.format("X-PacketProxy-HTTP2-Flags: %d\r\n", flags).toByteArray())
      buf.write(String.format("X-PacketProxy-HTTP2-UUID: %s\r\n", StringUtils.randomUUID()).toByteArray())
    } else {
      buf.write("X-PacketProxy-HTTP2-GRPC-2nd-Frame-Header: 1\r\n".toByteArray())
    }
    buf.write("\r\n".toByteArray())
    saveExtra(buf.toByteArray())
  }

  companion object {
    @JvmField val TYPE: Type = Type.HEADERS
    @JvmField val FLAG_END_STREAM: Byte = 0x01
    @JvmField val FLAG_END_HEADERS: Byte = 0x04
    @JvmField val FLAG_PADDED: Byte = 0x08
    @JvmField val FLAG_PRIORITY: Byte = 0x20
    @JvmField val FLAG_EXTRA: Byte = 0x40
  }
}
