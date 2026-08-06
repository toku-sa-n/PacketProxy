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
import java.util.HashMap
import org.eclipse.jetty.http2.hpack.HpackEncoder
import packetproxy.common.UniqueID
import packetproxy.http.Http
import packetproxy.http2.frames.*
import packetproxy.http2.frames.DataFrame
import packetproxy.http2.frames.Frame
import packetproxy.http2.frames.HeadersFrame
import packetproxy.model.Packet

open class Http2(private val uniqueId: UniqueID) : FramesBase() {
  private val clientStreamManager = StreamManager()
  private val serverStreamManager = StreamManager()
  private val groupMap: MutableMap<Long, Long> = HashMap()

  override fun getName(): String = "HTTP2"

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
    val out = ByteArrayOutputStream()
    for (frame in parseFrames(frames)) {
      if (frame is HeadersFrame) {
        out.write(frame.getHttp())
      } else if (frame is DataFrame) {
        out.write(frame.payload)
      }
    }
    val http = Http.create(out.toByteArray())
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
  override fun encodeClientRequestToFrames(http: ByteArray): ByteArray =
    encodeToFrames(http, getClientHpackEncoder())

  @Throws(Exception::class)
  override fun encodeServerResponseToFrames(http: ByteArray): ByteArray =
    encodeToFrames(http, getServerHpackEncoder())

  @Throws(Exception::class)
  private fun encodeToFrames(data: ByteArray, encoder: HpackEncoder): ByteArray {
    val out = ByteArrayOutputStream()
    val http = Http.create(data)
    var flags = http.getFirstHeader("X-PacketProxy-HTTP2-Flags").toInt()
    if (http.body.isNotEmpty()) {
      http.updateHeader(
        "X-PacketProxy-HTTP2-Flags",
        (flags and 0xff and HeadersFrame.FLAG_END_STREAM.toInt().inv()).toString(),
      )
      val headersFrame = HeadersFrame(http)
      out.write(headersFrame.toByteArrayWithoutExtra(encoder))
      val dataFrame = DataFrame(http)
      out.write(dataFrame.toByteArrayWithoutExtra())
    } else {
      http.updateHeader(
        "X-PacketProxy-HTTP2-Flags",
        (flags and 0xff or HeadersFrame.FLAG_END_STREAM.toInt()).toString(),
      )
      val headersFrame = HeadersFrame(http)
      out.write(headersFrame.toByteArrayWithoutExtra(encoder))
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
