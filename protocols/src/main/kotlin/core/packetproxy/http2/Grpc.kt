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

open class Grpc(private val uniqueId: UniqueID) : FramesBase() {
  private val clientStreamManager = StreamManager()
  private val serverStreamManager = StreamManager()
  private val groupMap: MutableMap<Long, Long> = HashMap()

  override fun getName(): String = "gRPC"

  @Throws(Exception::class)
  override fun passFramesToDecodeClientRequest(frames: List<Frame>): ByteArray? =
    filterFrames(clientStreamManager, frames)

  @Throws(Exception::class)
  override fun passFramesToDecodeServerResponse(frames: List<Frame>): ByteArray? =
    filterFrames(serverStreamManager, frames)

  @Throws(Exception::class)
  private fun filterFrames(streamManager: StreamManager, frames: List<Frame>): ByteArray? {
    var completedStreamId: Int? = null
    for (frame in frames) {
      if (frame is HeadersFrame) {
        streamManager.write(frame)
      } else if (frame is DataFrame) {
        streamManager.write(frame)
      }
      if ((frame.flags and 0x01) > 0) {
        completedStreamId = frame.streamId
      }
    }
    if (completedStreamId == null) {
      return null
    }
    val stream = streamManager.read(completedStreamId) ?: return null
    val result = toByteArray(stream)
    streamManager.clear(completedStreamId)
    return result
  }

  @Throws(Exception::class)
  override fun decodeClientRequestFromFrames(frames: ByteArray): ByteArray =
    decodeFromFrames(frames)

  @Throws(Exception::class)
  override fun decodeServerResponseFromFrames(frames: ByteArray): ByteArray =
    decodeFromFrames(frames)

  @Throws(Exception::class)
  private fun decodeFromFrames(frames: ByteArray): ByteArray {
    val outHeader = ByteArrayOutputStream()
    val outData = ByteArrayOutputStream()
    var httpHeaderSums: Http? = null

    for (frame in parseFrames(frames)) {
      if (frame is HeadersFrame) {
        val http = Http.create(frame.getHttp())
        if (httpHeaderSums == null) {
          httpHeaderSums = http
        } else {
          for (field in http.header.fields) {
            httpHeaderSums.updateHeader("x-trailer-" + field.getName(), field.getValue())
          }
        }
      } else if (frame is DataFrame) {
        outData.write(frame.payload)
      }
    }
    outHeader.write(httpHeaderSums!!.toByteArray())
    outData.writeTo(outHeader)
    val http = Http.create(outHeader.toByteArray())
    val flags = http.getFirstHeader("X-PacketProxy-HTTP2-Flags").toInt()
    if (http.body.isEmpty()) {
      http.updateHeader(
        "X-PacketProxy-HTTP2-Flags",
        (flags and 0xff or HeadersFrame.FLAG_END_STREAM.toInt()).toString(),
      )
    }
    return http.toByteArray()
  }

  @Throws(Exception::class)
  override fun encodeClientRequestToFrames(data: ByteArray): ByteArray =
    encodeToFrames(data, getClientHpackEncoder())

  @Throws(Exception::class)
  override fun encodeServerResponseToFrames(data: ByteArray): ByteArray =
    encodeToFrames(data, getServerHpackEncoder())

  @Throws(Exception::class)
  private fun encodeToFrames(data: ByteArray, encoder: HpackEncoder): ByteArray {
    val out = ByteArrayOutputStream()
    val http = Http.create(data)
    val flags = http.getFirstHeader("X-PacketProxy-HTTP2-Flags").toInt()
    val GRPC2ndHeaderHttpFields = HttpFields.build()

    val unusedHeaders: MutableList<String> = ArrayList()
    for (field in http.header.fields) {
      if (field.getName().startsWith("x-trailer-")) {
        unusedHeaders.add(field.getName())
        GRPC2ndHeaderHttpFields.add(field.getName().substring(10), field.getValue())
      }
    }
    for (name in unusedHeaders) {
      http.removeHeader(name)
    }
    val has_second_frame = http.body.isNotEmpty() || GRPC2ndHeaderHttpFields.size() > 0

    var first_flags = flags and 0xff or HeadersFrame.FLAG_END_STREAM.toInt()
    if (has_second_frame) {
      first_flags = flags and 0xff and HeadersFrame.FLAG_END_STREAM.toInt().inv()
    }
    http.updateHeader("X-PacketProxy-HTTP2-Flags", first_flags.toString())

    val headersFrame = HeadersFrame(http)
    out.write(headersFrame.toByteArrayWithoutExtra(encoder))

    if (http.body.isNotEmpty()) {
      val dataFrame = DataFrame(http)
      if (GRPC2ndHeaderHttpFields.size() > 0) {
        dataFrame.flags = dataFrame.flags and 0xff and DataFrame.FLAG_END_STREAM.toInt().inv()
      }
      out.write(dataFrame.toByteArrayWithoutExtra())
    }

    if (GRPC2ndHeaderHttpFields.size() > 0) {
      val althttp = http
      althttp.setBody(ByteArray(0))
      althttp.removeMatches("^(?!X-PacketProxy-HTTP2).*$")
      for (headerField in GRPC2ndHeaderHttpFields) {
        althttp.updateHeader(headerField.name, headerField.value)
      }
      althttp.updateHeader(
        "X-PacketProxy-HTTP2-Flags",
        (flags and 0xff or HeadersFrame.FLAG_END_STREAM.toInt()).toString(),
      )
      val headers2ndFrame = HeadersFrame(althttp)
      out.write(headers2ndFrame.toByteArrayWithoutExtra(encoder))
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
