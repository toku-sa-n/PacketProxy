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
/*
 * Copyright 2019,2026 DeNA Co., Ltd.
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
import java.io.InputStream
import java.util.LinkedList
import org.apache.commons.lang3.ArrayUtils
import org.eclipse.jetty.http2.hpack.HpackDecoder
import org.eclipse.jetty.http2.hpack.HpackEncoder
import packetproxy.http2.frames.DataFrame
import packetproxy.http2.frames.Frame
import packetproxy.http2.frames.FrameUtils
import packetproxy.http2.frames.GoawayFrame
import packetproxy.http2.frames.HeadersFrame
import packetproxy.http2.frames.PingFrame
import packetproxy.http2.frames.RstStreamFrame
import packetproxy.http2.frames.SettingsFrame
import packetproxy.http2.frames.SettingsFrame.SettingsFrameType
import packetproxy.http2.frames.WindowUpdateFrame
import packetproxy.util.Logging.err

open class FrameManager {
  private var hpackEncoder = HpackEncoder(4096, 65536)
  private var hpackDecoder: HpackDecoder? = null
  private val headersDataFrames: MutableList<Frame> = LinkedList()
  private val controlFrames: MutableList<Frame> = LinkedList()
  private val flowControlManager: FlowControlManager
  private var flag_receive_peer_settings = false
  private var flag_send_settings = false
  private var flag_send_end_settings = false
  private var streamIdRemapper: StreamIdRemapper? = null
  private val baos = ByteArrayOutputStream()

  @Throws(Exception::class)
  constructor() {
    flowControlManager = FlowControlManager()
  }

  fun setStreamIdRemapper(streamIdRemapper: StreamIdRemapper?) {
    this.streamIdRemapper = streamIdRemapper
  }

  fun getHpackDecoder(): HpackDecoder? = hpackDecoder

  fun getHpackEncoder(): HpackEncoder = hpackEncoder

  fun getFlowControlManager(): FlowControlManager = flowControlManager

  @Throws(Exception::class)
  fun write(frames: List<Frame>) {
    for (frame in frames) {
      analyzeFrame(frame)
    }
  }

  @Throws(Exception::class)
  fun write(frames: ByteArray) {
    for (frame in FrameUtils.parseFrames(frames, hpackDecoder)) {
      analyzeFrame(frame)
    }
  }

  @Throws(Exception::class)
  private fun analyzeFrame(frame: Frame) {
    when (frame) {
      is HeadersFrame -> headersDataFrames.add(frame)
      is DataFrame -> headersDataFrames.add(frame)
      is SettingsFrame -> {
        flowControlManager.setInitialWindowSize(frame)
        if ((frame.flags and 0x1) == 0) {
          val header_table_size = frame[SettingsFrameType.SETTINGS_HEADER_TABLE_SIZE]
          val header_list_size = frame[SettingsFrameType.SETTINGS_MAX_HEADER_LIST_SIZE]
          hpackDecoder = HpackDecoder(header_table_size, header_list_size)
          flag_receive_peer_settings = true
          if (!flag_send_end_settings && flag_send_settings) {
            flowControlManager.getOutputStream().write(FrameUtils.END_SETTINGS)
            flowControlManager.getOutputStream().flush()
            flag_send_end_settings = true
          }
        }
      }
      is GoawayFrame -> {
        if (frame.getErrorCode() != 0) {
          err("GoAway:%s", frame)
        }
      }
      is RstStreamFrame -> {
        if (frame.getErrorCode() != 0 && frame.getErrorCode() != 8) {
          err("RstStream:%s", frame)
        }
      }
      is WindowUpdateFrame -> flowControlManager.appendWindowSize(frame)
      is PingFrame -> {
        if ((frame.flags and 0x1) == 0) {
          val ack = Frame(Frame.Type.PING, 0x1, 0, frame.payload)
          flowControlManager.getOutputStream().write(ack.toByteArray())
          flowControlManager.getOutputStream().flush()
        }
      }
      else -> controlFrames.add(frame)
    }
  }

  @Throws(Exception::class)
  fun readControlFrames(): List<Frame> {
    val out: MutableList<Frame> = LinkedList()
    for (frame in controlFrames) {
      out.add(frame)
    }
    controlFrames.clear()
    return out
  }

  @Throws(Exception::class)
  fun readHeadersDataFrames(): List<Frame> {
    val out: MutableList<Frame> = LinkedList()
    for (frame in headersDataFrames) {
      out.add(frame)
    }
    headersDataFrames.clear()
    return out
  }

  @Throws(Exception::class)
  fun putToFlowControlledQueue(frameData: ByteArray) {
    baos.write(frameData)
    baos.flush()
    var length: Int
    while (true) {
      length = FrameUtils.checkDelimiter(baos.toByteArray())
      if (length <= 0) break
      val frame = ArrayUtils.subarray(baos.toByteArray(), 0, length)
      val remaining = ArrayUtils.subarray(baos.toByteArray(), length, baos.size())
      baos.reset()
      baos.write(remaining)
      baos.flush()
      if (FrameUtils.isPreface(frame)) {
        flowControlManager.getOutputStream().write(frame)
        flowControlManager.getOutputStream().flush()
      } else {
        val f = Frame(frame)
        remapOutgoingStreamId(f)
        flowControlManager.write(f)
        if (f.type == Frame.Type.SETTINGS) {
          flag_send_settings = true
          if (!flag_send_end_settings && flag_receive_peer_settings) {
            flowControlManager.getOutputStream().write(FrameUtils.END_SETTINGS)
            flowControlManager.getOutputStream().flush()
            flag_send_end_settings = true
          }
        }
      }
    }
  }

  private fun remapOutgoingStreamId(f: Frame) {
    if (streamIdRemapper == null || f.streamId == 0) {
      return
    }
    if (f.type == Frame.Type.HEADERS) {
      f.streamId = streamIdRemapper!!.mapClientToServer(f.streamId, true)
    } else if (f.type == Frame.Type.DATA) {
      f.streamId = streamIdRemapper!!.mapClientToServer(f.streamId, false)
    }
  }

  @Throws(Exception::class)
  fun closeFlowControlledQueue() {
    flowControlManager.getOutputStream().close()
  }

  fun getFlowControlledInputStream(): InputStream = flowControlManager.getInputStream()
}
