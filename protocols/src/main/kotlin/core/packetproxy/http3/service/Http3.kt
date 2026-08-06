/*
 * Copyright 2022 DeNA Co., Ltd.
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
package packetproxy.http3.service

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import org.eclipse.jetty.http.HttpFields
import org.eclipse.jetty.http.HttpStatus
import org.eclipse.jetty.http.HttpURI
import org.eclipse.jetty.http.HttpVersion
import org.eclipse.jetty.http.MetaData
import packetproxy.common.UniqueID
import packetproxy.http.Http
import packetproxy.http3.utils.streamIdLong
import packetproxy.http3.value.Setting
import packetproxy.model.Packet
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.QuicMessages
import packetproxy.quic.value.StreamId
import packetproxy.util.rethrow

open class Http3(private val uniqueId: UniqueID) {
  private val clientStreamsReader = StreamsReader(Constants.Role.CLIENT)
  private val clientStreamsWriter = StreamsWriter(Constants.Role.CLIENT)
  private val serverStreamsReader = StreamsReader(Constants.Role.SERVER)
  private val serverStreamsWriter = StreamsWriter(Constants.Role.SERVER)
  private val clientDecoder = Http3HeaderDecoder()
  private val serverDecoder = Http3HeaderDecoder()
  private val serverEncoder = Http3HeaderEncoder(0)
  private var clientEncoder: Http3HeaderEncoder? = null
  private var serverSetting: Setting? = null
  private val groupMap: MutableMap<Long, Long> = HashMap()

  init {
    serverStreamsWriter.writeSetting(Setting.generateWithDefaultValue())
    clientStreamsWriter.writeSetting(Setting.generateWithDefaultValue())
  }

  fun checkDelimiter(input: ByteArray?): Int {
    if (input == null || input.size < 16) {
      return -1
    }
    val buffer = ByteBuffer.wrap(input)
    buffer.getLong()
    val streamDataSize = buffer.getLong()
    val quicMsgSize = (8 + 8 + streamDataSize).toInt()
    return if (quicMsgSize <= input.size) quicMsgSize else -1
  }

  @Throws(Exception::class)
  fun clientRequestArrived(input: ByteArray) {
    val msgs = QuicMessages.parse(input)
    clientStreamsReader.write(msgs)
  }

  @Throws(Exception::class)
  fun passThroughClientRequest(): ByteArray {
    if (clientEncoder == null) {
      clientStreamsReader.getSetting().ifPresent { setting ->
        clientEncoder = Http3HeaderEncoder(setting.qpackMaxTableCapacity)
      }
    }

    val encode = clientStreamsReader.readQpackEncodeData()
    clientDecoder.putInstructions(encode)

    clientEncoder?.let { encoder ->
      val decode = clientStreamsReader.readQpackDecodeData()
      encoder.putInstructions(decode)
    }

    val msgs = serverStreamsWriter.readQuicMessages()
    return msgs.getBytes()
  }

  @Throws(Exception::class)
  fun generateReqHttp(httpRaw: HttpRaw): ByteArray {
    val http = ByteArrayOutputStream()
    clientDecoder
      .decode(httpRaw.getStreamId().streamIdLong(), httpRaw.getEncodedHeader())
      .forEach(
        rethrow { metaData ->
          val req = metaData as MetaData.Request
          val method = req.method
          val uri = req.uri
          val authority = uri.authority
          val path = uri.path
          val query = uri.query
          val queryStr = if (!query.isNullOrEmpty()) "?$query" else ""

          http.write(String.format("%s %s%s HTTP/3\r\n", method, path, queryStr).toByteArray())
          req.fields.forEach(
            rethrow { field ->
              http.write(String.format("%s: %s\r\n", field.name, field.value).toByteArray())
            }
          )
          http.write(String.format("x-packetproxy-http3-host: %s\r\n", authority).toByteArray())
        }
      )
    http.write(
      String.format("x-packetproxy-http3-stream-id: %d\r\n", httpRaw.getStreamId().streamIdLong())
        .toByteArray()
    )
    http.write("\r\n".toByteArray())
    clientStreamsWriter.writeQpackDecodeData(clientDecoder.getInstructions())
    http.write(httpRaw.getBody())
    return http.toByteArray()
  }

  @Throws(Exception::class)
  fun generateResHttp(httpRaw: HttpRaw): ByteArray {
    val http = ByteArrayOutputStream()
    serverDecoder
      .decode(httpRaw.getStreamId().streamIdLong(), httpRaw.getEncodedHeader())
      .forEach(
        rethrow { metaData ->
          val res = metaData as MetaData.Response
          http.write(
            String.format("HTTP/3 %d %s\r\n", res.status, HttpStatus.getMessage(res.status))
              .toByteArray()
          )
          res.fields.forEach(
            rethrow { field ->
              http.write(String.format("%s: %s\r\n", field.name, field.value).toByteArray())
            }
          )
        }
      )
    http.write(
      String.format("x-packetproxy-http3-stream-id: %d\r\n", httpRaw.getStreamId().streamIdLong())
        .toByteArray()
    )
    http.write("\r\n".toByteArray())
    serverStreamsWriter.writeQpackDecodeData(serverDecoder.getInstructions())
    http.write(httpRaw.getBody())
    return http.toByteArray()
  }

  @Throws(Exception::class)
  fun generateHttpRaw(httpBytes: ByteArray): HttpRaw = generateHttpRaw(Http.create(httpBytes))

  @Throws(Exception::class)
  fun generateHttpRaw(http: Http): HttpRaw {
    val method = http.method
    var uriString = ""
    var streamId: StreamId? = null
    val version = HttpVersion.fromString("HTTP/3.0")

    val headers = http.getHeader()
    var mutableFields = HttpFields.build()
    for (field in headers.fields) {
      when (field.getName()) {
        "x-packetproxy-http3-host" -> {
          val scheme = "https"
          val authority = field.getValue()
          val path = http.path
          val query = http.getQueryAsString()
          val queryStr = if (!query.isNullOrEmpty()) "?$query" else ""
          uriString = "$scheme://$authority$path$queryStr"
        }
        "x-packetproxy-http3-stream-id" -> {
          streamId = StreamId.of(field.getValue().toLong())
        }
        else -> mutableFields.add(field.getName(), field.getValue())
      }
    }
    var fields: HttpFields = mutableFields

    val meta: MetaData
    if (http.isRequest) {
      var contentLength = 0L
      if (method == "GET" || method == "HEAD") {
        contentLength = if (http.body.isEmpty()) Long.MIN_VALUE else http.body.size.toLong()
      } else if (method == "POST" || method == "PUT") {
        contentLength = http.body.size.toLong()
        mutableFields.add("content-length", contentLength.toString())
        fields = mutableFields
      }
      val uri = HttpURI.build().uri(uriString)
      meta = MetaData.Request(method, uri, version, fields, contentLength)
    } else {
      val contentLength = if (http.body.isEmpty()) Long.MIN_VALUE else http.body.size.toLong()
      meta = MetaData.Response(version, http.statusCode!!.toInt(), fields, contentLength)
    }

    val encodedHeader: ByteArray
    if (http.isRequest) {
      encodedHeader = serverEncoder.encode(streamId!!.streamIdLong(), meta)
      serverStreamsWriter.writeQpackEncodeData(serverEncoder.getInstructions())
    } else {
      encodedHeader = clientEncoder!!.encode(streamId!!.streamIdLong(), meta)
      clientStreamsWriter.writeQpackEncodeData(clientEncoder!!.getInstructions())
    }
    val body = http.body

    return HttpRaw.of(streamId!!, encodedHeader, body)
  }

  @Throws(Exception::class)
  fun clientRequestAvailable(): ByteArray {
    val bytes = ByteArrayOutputStream()
    clientStreamsReader
      .readHttpRaw()
      .ifPresent(rethrow { httpRaw -> bytes.write(generateReqHttp(httpRaw)) })
    return bytes.toByteArray()
  }

  @Throws(Exception::class) fun decodeClientRequest(input: ByteArray): ByteArray = input

  @Throws(Exception::class)
  fun encodeClientRequest(input: ByteArray): ByteArray {
    val httpRaw = generateHttpRaw(input)
    serverStreamsWriter.write(httpRaw)
    return serverStreamsWriter.readQuicMessages().getBytes()
  }

  @Throws(Exception::class)
  fun serverResponseArrived(input: ByteArray) {
    val msgs = QuicMessages.parse(input)
    serverStreamsReader.write(msgs)
  }

  @Throws(Exception::class)
  fun passThroughServerResponse(): ByteArray {
    if (serverSetting == null) {
      serverStreamsReader.getSetting().ifPresent { setting -> serverSetting = setting }
    }
    val encode = serverStreamsReader.readQpackEncodeData()
    serverDecoder.putInstructions(encode)

    val decode = serverStreamsReader.readQpackDecodeData()
    serverEncoder.putInstructions(decode)

    val msgs = clientStreamsWriter.readQuicMessages()
    return msgs.getBytes()
  }

  @Throws(Exception::class)
  fun serverResponseAvailable(): ByteArray {
    val bytes = ByteArrayOutputStream()
    serverStreamsReader
      .readHttpRaw()
      .ifPresent(rethrow { httpRaw -> bytes.write(generateResHttp(httpRaw)) })
    return bytes.toByteArray()
  }

  @Throws(Exception::class) fun decodeServerResponse(input: ByteArray): ByteArray = input

  @Throws(Exception::class)
  fun encodeServerResponse(input: ByteArray): ByteArray {
    val httpRaw = generateHttpRaw(input)
    clientStreamsWriter.write(httpRaw)
    return clientStreamsWriter.readQuicMessages().getBytes()
  }

  @Throws(Exception::class)
  fun setGroupId(packet: Packet) {
    val data =
      if (packet.getDecodedData().isNotEmpty()) packet.getDecodedData()
      else packet.getModifiedData()
    val http = Http.create(data)
    val streamIdStr = http.getFirstHeader("x-packetproxy-http3-stream-id")
    if (streamIdStr.isNotEmpty()) {
      val streamId = streamIdStr.toLong()
      if (groupMap.containsKey(streamId)) {
        packet.setGroup(groupMap[streamId]!!)
      } else {
        val groupId = uniqueId.createId()
        groupMap[streamId] = groupId
        packet.setGroup(groupId)
      }
    }
  }
}
