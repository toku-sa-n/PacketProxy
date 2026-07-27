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
import java.util.LinkedList
import packetproxy.http2.frames.Frame

open class StreamManager {
  private val streamMap: MutableMap<Int, MutableList<Frame>> = HashMap()

  fun write(frame: Frame) {
    var stream = streamMap[frame.streamId]
    if (stream == null) {
      stream = LinkedList()
      streamMap[frame.streamId] = stream
    }
    stream.add(frame)
  }

  fun read(streamId: Int): List<Frame>? = streamMap[streamId]

  fun entrySet(): Set<Map.Entry<Int, MutableList<Frame>>> = streamMap.entries

  fun clear(streamId: Int) {
    streamMap.remove(streamId)
  }

  @Throws(Exception::class)
  fun mergePayload(streamId: Int): ByteArray {
    val out = ByteArrayOutputStream()
    for (frame in read(streamId)!!) {
      out.write(frame.payload)
    }
    return out.toByteArray()
  }

  @Throws(Exception::class)
  fun toByteArray(streamId: Int): ByteArray {
    val out = ByteArrayOutputStream()
    for (frame in read(streamId)!!) {
      out.write(frame.toByteArray())
    }
    return out.toByteArray()
  }

  fun popOneFrame(): Frame? {
    if (streamMap.isEmpty()) return null
    val streamId = streamMap.keys.stream().findFirst().get()
    return popOneFrame(streamId)
  }

  fun popOneFrame(streamId: Int): Frame {
    val frame = streamMap[streamId]!!.removeAt(0)
    if (streamMap[streamId]!!.isEmpty()) {
      clear(streamId)
    }
    return frame
  }
}
