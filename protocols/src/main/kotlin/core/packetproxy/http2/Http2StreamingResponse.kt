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
import java.util.ArrayDeque
import java.util.HashMap
import java.util.Queue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.eclipse.jetty.http2.hpack.HpackEncoder
import packetproxy.common.UniqueID
import packetproxy.http.Http
import packetproxy.http2.frames.*
import packetproxy.http2.frames.DataFrame
import packetproxy.http2.frames.Frame
import packetproxy.http2.frames.HeadersFrame
import packetproxy.model.Packet
import packetproxy.model.Packets
import packetproxy.util.errWithStackTrace

open class Http2StreamingResponse(private val packets: Packets, private val uniqueId: UniqueID) :
  FramesBase() {
  private val clientStreamManager = StreamManager()
  private val serverStreamManager = StreamManager()
  private val stream = StreamManager()
  private val frameQueue: Queue<Frame> = ArrayDeque()
  private val groupMap: MutableMap<Long, Long> = HashMap()

  companion object {
    private val DATA_UPDATE_POOL: ExecutorService =
      Executors.newCachedThreadPool { r ->
        Thread(r, "pp-http2-streaming-data").apply { isDaemon = true }
      }
  }

  @Throws(Exception::class)
  override fun passThroughServerResponse(): ByteArray {
    val out = ByteArrayOutputStream()
    if (!alreadySentClientRequestEpilogue) {
      out.write(SETTINGS)
      out.write(WINDOW_UPDATE)
      alreadySentClientRequestEpilogue = true
    }
    for (frame in serverFrameManager.readControlFrames()) {
      out.write(frame.toByteArray())
    }
    for (frame in serverFrameManager.readHeadersDataFrames()) {
      if (frame is HeadersFrame) {
        out.write(frame.toByteArrayWithoutExtra(getServerHpackEncoder(), true))
        frameQueue.add(frame)
        synchronized(stream) { stream.write(frame) }
      } else {
        out.write(frame.toByteArray())
        synchronized(stream) { stream.write(frame) }
        val streamId = frame.streamId
        DATA_UPDATE_POOL.execute {
          try {
            val data = ByteArrayOutputStream()
            synchronized(stream) {
              for (f in stream.read(streamId)!!) {
                if (f is HeadersFrame) {
                  data.write(f.getExtra())
                } else {
                  data.write(f.payload)
                }
              }
            }
            val http = Http.create(data.toByteArray())
            if (http.body.isNotEmpty()) {
              val matchingPackets =
                packets.queryFullText(http.getFirstHeader("X-PacketProxy-HTTP2-UUID"))
              for (packet in matchingPackets) {
                val p = packets.query(packet.getId())!!
                p.setDecodedData(http.toByteArray())
                p.setModifiedData(http.toByteArray())
                packets.update(p)
              }
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    }
    return out.toByteArray()
  }

  @Throws(Exception::class)
  override fun passFramesToDecodeClientRequest(frames: List<Frame>): ByteArray? =
    filterFrames(clientStreamManager, frames)

  @Throws(Exception::class)
  override fun passFramesToDecodeServerResponse(frames: List<Frame>): ByteArray? {
    val frame = frameQueue.poll()
    return if (frame != null) {
      frame.toByteArray()
    } else {
      filterFrames(serverStreamManager, frames)
    }
  }

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
    val streamFrames = streamManager.read(completedStreamId) ?: return null
    val result = toByteArray(streamFrames)
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
  override fun encodeClientRequestToFrames(data: ByteArray): ByteArray =
    encodeToFrames(data, getClientHpackEncoder())

  @Throws(Exception::class)
  override fun encodeServerResponseToFrames(data: ByteArray): ByteArray? = null

  @Throws(Exception::class)
  private fun encodeToFrames(data: ByteArray, encoder: HpackEncoder): ByteArray {
    val out = ByteArrayOutputStream()
    val http = Http.create(data)
    val headersFrame = HeadersFrame(http)
    out.write(headersFrame.toByteArrayWithoutExtra(encoder))
    if (http.body.isNotEmpty()) {
      val dataFrame = DataFrame(http)
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
