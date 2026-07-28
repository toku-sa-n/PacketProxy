/*
 * Copyright 2026 DeNA Co., Ltd.
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

import java.util.HashMap
import org.apache.commons.lang3.ArrayUtils
import packetproxy.http2.frames.*
import packetproxy.http2.frames.Frame

/**
 * Remaps HTTP/2 stream IDs between the client-facing and the server-facing connection.
 *
 * <p>PacketProxy terminates the two connections independently and forwards each request only after
 * it has been fully buffered (see `Http2#filterFrames`). Concurrent requests can therefore reach
 * the server in a different order than the client opened them, which violates RFC 7540 5.1.1 ("The
 * identifier of a newly established stream MUST be numerically greater than all streams that the
 * initiating endpoint has opened") and makes the server abort the connection with
 * `GOAWAY(PROTOCOL_ERROR)`.
 *
 * <p>This class assigns a fresh, monotonically increasing server stream ID to each client stream in
 * the order the request is actually sent to the server, and maps the server's response stream IDs
 * back to the client's. Only HEADERS and DATA frames carry stream IDs that need remapping here;
 * connection-level frames (stream 0) and consumed control frames (WINDOW_UPDATE / RST_STREAM, kept
 * in server-ID space for flow control) are left as-is.
 */
open class StreamIdRemapper {
  private val clientToServer: MutableMap<Int, Int> = HashMap()
  private val serverToClient: MutableMap<Int, Int> = HashMap()
  private var nextServerStreamId = 1

  @Synchronized
  fun mapClientToServer(clientStreamId: Int, allocateIfAbsent: Boolean): Int {
    var serverStreamId = clientToServer[clientStreamId]
    if (serverStreamId == null) {
      if (!allocateIfAbsent) {
        return clientStreamId
      }
      serverStreamId = nextServerStreamId
      nextServerStreamId += 2
      clientToServer[clientStreamId] = serverStreamId
      serverToClient[serverStreamId] = clientStreamId
    }
    return serverStreamId
  }

  @Synchronized
  fun mapServerToClient(serverStreamId: Int): Int {
    val clientStreamId = serverToClient[serverStreamId]
    return clientStreamId ?: serverStreamId
  }

  @Synchronized
  @Throws(Exception::class)
  fun rewriteResponseToClient(frames: ByteArray): ByteArray {
    val out = frames.clone()
    var pos = 0
    while (pos < out.size) {
      val remaining = ArrayUtils.subarray(out, pos, out.size)
      val delim = checkDelimiter(remaining)
      if (delim <= 0) {
        break
      }
      if (!isPreface(remaining)) {
        val type = out[pos + 3].toInt() and 0xff
        if (type == TYPE_HEADERS || type == TYPE_DATA) {
          val serverStreamId = readStreamId(out, pos)
          if (serverStreamId != 0) {
            writeStreamId(out, pos, mapServerToClient(serverStreamId))
          }
        }
      }
      pos += delim
    }
    return out
  }

  companion object {
    private val TYPE_DATA = Frame.Type.DATA.ordinal
    private val TYPE_HEADERS = Frame.Type.HEADERS.ordinal

    private fun readStreamId(data: ByteArray, frameOffset: Int): Int =
      ((data[frameOffset + 5].toInt() and 0x7f) shl 24) or
        ((data[frameOffset + 6].toInt() and 0xff) shl 16) or
        ((data[frameOffset + 7].toInt() and 0xff) shl 8) or
        (data[frameOffset + 8].toInt() and 0xff)

    private fun writeStreamId(data: ByteArray, frameOffset: Int, streamId: Int) {
      data[frameOffset + 5] =
        ((data[frameOffset + 5].toInt() and 0x80) or ((streamId ushr 24) and 0x7f)).toByte()
      data[frameOffset + 6] = ((streamId ushr 16) and 0xff).toByte()
      data[frameOffset + 7] = ((streamId ushr 8) and 0xff).toByte()
      data[frameOffset + 8] = (streamId and 0xff).toByte()
    }
  }
}
