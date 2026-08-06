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
import org.apache.commons.lang3.ArrayUtils
import packetproxy.http2.frames.*
import packetproxy.http2.frames.DataFrame
import packetproxy.http2.frames.Frame
import packetproxy.util.err

open class FlowControl(val streamId: Int, initialWindowSize: Int) {
  var windowSize: Int = initialWindowSize
    private set

  var headersFrame: Frame? = null
    private set

  var grpcHeaderFrame: Frame? = null
    private set

  var headersFrameSent = false
    private set

  var dataFrameSent = false
    private set

  var grpcHeadersFrameSent = false
    private set

  private val queue = ByteArrayOutputStream()
  private var end_flag = false
  private var empty_data_end_flag = false

  fun appendWindowSize(appendWindowSize: Int) {
    synchronized(queue) {
      windowSize =
        (windowSize.toLong() + appendWindowSize.toLong()).coerceAtMost(MAX_WINDOW_SIZE).toInt()
    }
  }

  fun pushHeadersFrame(headersFrame: Frame) {
    if (this.headersFrame == null) {
      this.headersFrame = headersFrame
    } else {
      this.grpcHeaderFrame = headersFrame
    }
  }

  @Throws(Exception::class)
  fun enqueue(frame: Frame) {
    synchronized(queue) {
      if (queue.size() + frame.payload.size > MAX_QUEUED_BYTES) {
        throw IllegalStateException(
          "HTTP/2 FlowControl queue exceeded max size ($MAX_QUEUED_BYTES) for streamId=$streamId"
        )
      }
      queue.write(frame.payload)
      queue.flush()
      if ((frame.flags and DataFrame.FLAG_END_STREAM.toInt()) > 0) {
        end_flag = true
        if (queue.size() == 0) {
          empty_data_end_flag = true
        }
      }
    }
  }

  @Synchronized
  @Throws(Exception::class)
  fun dequeue(connectionWindowSize: Int): Stream? {
    val stream = Stream()

    if (!this.headersFrameSent && this.headersFrame != null) {
      stream.write(this.headersFrame!!)
      this.headersFrameSent = true
      return stream
    }

    if (
      this.headersFrameSent &&
        (this.dataFrameSent || queue.size() == 0) &&
        !this.grpcHeadersFrameSent &&
        this.grpcHeaderFrame != null
    ) {
      stream.write(this.grpcHeaderFrame!!)
      this.grpcHeadersFrameSent = true
      return stream
    }

    if (queue.size() == 0) {
      if (empty_data_end_flag) {
        empty_data_end_flag = false
        val flags = DataFrame.FLAG_END_STREAM.toInt()
        val frame = create(DataFrame.TYPE, flags, streamId, ByteArray(0))
        stream.write(frame)
        return stream
      }
      return null
    }

    val capacity = minOf(windowSize, connectionWindowSize)
    if (capacity == 0) {
      err(
        "[HTTP/2 FlowControl] try to send %d data, but running out of window (streamId: %d)",
        queue.size(),
        this.streamId,
      )
      return null
    }
    val dataLen = minOf(queue.size(), capacity)
    if (dataLen == 0) {
      err("[HTTP/2 FlowControl] sending data is not found (streamId: %d)", this.streamId)
      return null
    }
    this.windowSize -= dataLen
    var data = ArrayUtils.subarray(queue.toByteArray(), 0, dataLen)
    val remaining = ArrayUtils.subarray(queue.toByteArray(), dataLen, queue.size())
    queue.reset()
    queue.write(remaining)
    queue.flush()

    while (data.isNotEmpty()) {
      val payloadLen = minOf(data.size, 16384)
      val payload = ArrayUtils.subarray(data, 0, payloadLen)
      data = ArrayUtils.subarray(data, payloadLen, data.size)

      var flags = 0x0
      if (remaining.isEmpty() && end_flag && data.isEmpty()) {
        flags = DataFrame.FLAG_END_STREAM.toInt()
      }
      val frame = create(DataFrame.TYPE, flags, streamId, payload)

      if (remaining.isEmpty() && data.isEmpty()) {
        this.dataFrameSent = true
      }

      stream.write(frame)
    }

    if (
      this.headersFrameSent &&
        this.dataFrameSent &&
        !this.grpcHeadersFrameSent &&
        this.grpcHeaderFrame != null
    ) {
      stream.write(this.grpcHeaderFrame!!)
      this.grpcHeadersFrameSent = true
    }

    return stream
  }

  fun size(): Int {
    synchronized(queue) {
      return queue.size()
    }
  }

  companion object {
    const val MAX_QUEUED_BYTES = 64 * 1024 * 1024
    const val MAX_WINDOW_SIZE = 0x7FFFFFFFL
  }
}
