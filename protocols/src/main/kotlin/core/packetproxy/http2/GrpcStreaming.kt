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
package packetproxy.http2

import java.io.ByteArrayOutputStream
import java.util.ArrayList
import java.util.HashMap
import org.eclipse.jetty.http.HttpFields
import org.eclipse.jetty.http2.hpack.HpackEncoder
import packetproxy.common.UniqueID
import packetproxy.http.Http
import packetproxy.http2.frames.*
import packetproxy.http2.frames.DataFrame
import packetproxy.http2.frames.Frame
import packetproxy.http2.frames.HeadersFrame
import packetproxy.model.Packet

open class GrpcStreaming(private val uniqueId: UniqueID) : FramesBase() {
  private val clientStreamManager = StreamManager()
  private val serverStreamManager = StreamManager()
  private val clientStreamFirstHeaderMap: MutableMap<Int, HeadersFrame> = HashMap()
  private val serverStreamFirstHeaderMap: MutableMap<Int, HeadersFrame> = HashMap()
  private val groupMap: MutableMap<Long, Long> = HashMap()

  override fun getName(): String = "gRPCStreaming"

  @Throws(Exception::class)
  override fun passFramesToDecodeClientRequest(frames: List<Frame>): ByteArray? =
    filterFrames(clientStreamManager, frames)

  @Throws(Exception::class)
  override fun passFramesToDecodeServerResponse(frames: List<Frame>): ByteArray? =
    filterFrames(serverStreamManager, frames)

  @Throws(Exception::class)
  private fun filterFrames(streamManager: StreamManager, frames: List<Frame>): ByteArray {
    for (frame in frames) {
      streamManager.write(frame)
    }
    val frame = streamManager.popOneFrame() ?: return ByteArray(0)
    return frame.toByteArray()
  }

  @Throws(Exception::class)
  override fun decodeClientRequestFromFrames(frames: ByteArray): ByteArray =
    decodeFromFrames(frames, clientStreamFirstHeaderMap)

  @Throws(Exception::class)
  override fun decodeServerResponseFromFrames(frames: ByteArray): ByteArray =
    decodeFromFrames(frames, serverStreamFirstHeaderMap)

  @Throws(Exception::class)
  private fun decodeFromFrames(
    frames: ByteArray,
    streamFirstHeaderMap: MutableMap<Int, HeadersFrame>,
  ): ByteArray {
    val outHeader = ByteArrayOutputStream()
    val outData = ByteArrayOutputStream()
    var httpHeaderSums: Http? = null

    val parsedFrames = parseFrames(frames)
    if (parsedFrames.size != 1) {
      throw Exception("処理対象のフレームが複数あります")
    }
    for (frame in parsedFrames) {
      var firstHeaderFrame = streamFirstHeaderMap[frame.streamId]
      val isFirstHeaderFrame = firstHeaderFrame == null
      if (isFirstHeaderFrame) {
        if (frame !is HeadersFrame) {
          throw Exception("ヘッダフレームの前にデータフレームがあります")
        }
        firstHeaderFrame = frame
        streamFirstHeaderMap[frame.streamId] = frame
        httpHeaderSums = Http.create(firstHeaderFrame.getHttp())
      } else if (frame is HeadersFrame) {
        httpHeaderSums = Http.create(firstHeaderFrame!!.getHttp())
        val http = Http.create(frame.getHttp())
        for (field in http.header.fields) {
          httpHeaderSums.updateHeader("x-trailer-" + field.getName(), field.getValue())
        }
        httpHeaderSums.updateHeader("X-PacketProxy-HTTP2-TrailerHeaderFrame", "true")
        httpHeaderSums.path = "/trailer-header-frame"
      } else {
        httpHeaderSums = Http.create(firstHeaderFrame!!.getHttp())
        outData.write(frame.payload)
        httpHeaderSums.path = "/data-frame"
        httpHeaderSums.updateHeader("X-PacketProxy-HTTP2-Type", "0")
      }
      val flags = frame.flags
      httpHeaderSums!!.updateHeader("X-PacketProxy-HTTP2-Flags", (flags and 0xff).toString())
      if (!isFirstHeaderFrame) {
        val unusedHeaders: MutableList<String> = ArrayList()
        for (field in httpHeaderSums.header.fields) {
          if (
            field.getName().startsWith("X-PacketProxy") || field.getName().startsWith("x-trailer-")
          ) {
            continue
          }
          unusedHeaders.add(field.getName())
        }
        for (name in unusedHeaders) {
          httpHeaderSums.removeHeader(name)
        }
      }
    }
    outHeader.write(httpHeaderSums!!.toByteArray())
    outData.writeTo(outHeader)
    val http = Http.create(outHeader.toByteArray())
    return http.toByteArray()
  }

  @Throws(Exception::class)
  override fun encodeClientRequestToFrames(http: ByteArray): ByteArray =
    encodeToFrames(http, getClientHpackEncoder())

  @Throws(Exception::class)
  override fun encodeServerResponseToFrames(http: ByteArray): ByteArray =
    encodeToFrames(http, getServerHpackEncoder())

  @Throws(Exception::class)
  private fun encodeToFrames(data: ByteArray, encoder: HpackEncoder): ByteArray {
    val out = ByteArrayOutputStream()
    val http = Http.create(data)
    val flags = http.getFirstHeader("X-PacketProxy-HTTP2-Flags").toInt()
    val GRPC2ndHeaderHttpFields = HttpFields.build()

    val unusedHeaders: MutableList<String> = ArrayList()
    var isTrailerHeaderFrame = false
    var isDataFrame = false
    for (field in http.header.fields) {
      if (field.getName().startsWith("x-trailer-")) {
        unusedHeaders.add(field.getName())
        GRPC2ndHeaderHttpFields.add(field.getName().substring(10), field.getValue())
      } else if (field.getName() == "X-PacketProxy-HTTP2-TrailerHeaderFrame") {
        isTrailerHeaderFrame = true
      } else if (field.getName() == "X-PacketProxy-HTTP2-Type" && field.getValue().toInt() == 0) {
        isDataFrame = true
      }
    }
    for (name in unusedHeaders) {
      http.removeHeader(name)
    }

    if (!isTrailerHeaderFrame && !isDataFrame) {
      val headersFrame = HeadersFrame(http)
      out.write(headersFrame.toByteArrayWithoutExtra(encoder, false, false))
    } else if (isTrailerHeaderFrame) {
      val althttp = http
      althttp.setBody(ByteArray(0))
      althttp.removeMatches("^(?!X-PacketProxy-HTTP2).*$")
      for (headerField in GRPC2ndHeaderHttpFields) {
        althttp.updateHeader(headerField.name, headerField.value)
      }
      althttp.updateHeader("X-PacketProxy-HTTP2-Flags", flags.toString())
      val headers2ndFrame = HeadersFrame(althttp)
      out.write(headers2ndFrame.toByteArrayWithoutExtra(encoder))
    } else {
      val dataFrame = DataFrame(http)
      dataFrame.flags = flags
      out.write(dataFrame.toByteArrayWithoutExtra())
    }
    return out.toByteArray()
  }

  @Throws(Exception::class)
  override fun setGroupId(packet: Packet) {
    val data =
      if (packet.getDecodedData().isNotEmpty()) packet.getDecodedData()
      else packet.getModifiedData()
    val http = Http.create(data)
    val streamIdStr = http.getFirstHeader("X-PacketProxy-HTTP2-Stream-Id")
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
