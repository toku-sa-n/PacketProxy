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

import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.HashMap
import packetproxy.http2.frames.Frame
import packetproxy.http2.frames.SettingsFrame
import packetproxy.http2.frames.SettingsFrame.SettingsFrameType
import packetproxy.http2.frames.WindowUpdateFrame
import packetproxy.util.Logging.err

open class FlowControlManager {
  private val flows: MutableMap<Int, FlowControl> = HashMap()
  private val PIPE_SIZE = 65535
  private var connectionWindowSize = 65535
  private var initialStreamWindowSize = 65535
  private var maxConcurrentStreams = 100
  private val outputForFlowControl: PipedOutputStream
  private val inputForFlowControl: PipedInputStream

  @Throws(Exception::class)
  constructor() {
    outputForFlowControl = PipedOutputStream()
    inputForFlowControl = PipedInputStream(outputForFlowControl, PIPE_SIZE)
  }

  @Synchronized
  private fun getFlow(streamId: Int): FlowControl {
    var flow = flows[streamId]
    if (flow == null) {
      flow = FlowControl(streamId, initialStreamWindowSize)
      flows[streamId] = flow
    }
    return flow
  }

  @Synchronized
  @Throws(Exception::class)
  private fun writeData(flow: FlowControl) {
    val stream = flow.dequeue(this.connectionWindowSize)
    if (stream != null) {
      this.connectionWindowSize -= stream.payloadSize()
      this.outputForFlowControl.write(stream.toByteArrayWithoutExtra())
      this.outputForFlowControl.flush()
    }
  }

  @Synchronized
  fun setInitialWindowSize(frame: SettingsFrame) {
    val flags = frame.flags
    if ((flags and 0x1) > 0) {
      return
    }
    if (initialStreamWindowSize != 65535) {
      err("[Error] Initial window size is reset. We cannot handle it (not implemented yet)")
    }
    initialStreamWindowSize = frame[SettingsFrameType.SETTINGS_INITIAL_WINDOW_SIZE]
  }

  @Synchronized
  fun setMaxConcurrentStreams(frame: SettingsFrame) {
    val flags = frame.flags
    if ((flags and 0x1) > 0) {
      return
    }
    maxConcurrentStreams = frame[SettingsFrameType.SETTINGS_MAX_CONCURRENT_STREAMS]
  }

  @Synchronized
  @Throws(Exception::class)
  fun appendWindowSize(frame: WindowUpdateFrame) {
    val streamId = frame.streamId
    val windowSize = frame.getWindowSize()

    if (streamId == 0) {
      connectionWindowSize += windowSize
      for (flow in flows.values) {
        writeData(flow)
      }
    } else {
      val flow = getFlow(streamId)
      flow.appendWindowSize(windowSize)
      writeData(flow)
    }
  }

  @Synchronized
  @Throws(Exception::class)
  fun write(frame: Frame) {
    if (frame.type == Frame.Type.HEADERS) {
      val flow = getFlow(frame.streamId)
      flow.pushHeadersFrame(frame)
      writeData(flow)
    } else if (frame.type == Frame.Type.DATA) {
      val flow = getFlow(frame.streamId)
      flow.enqueue(frame)
      writeData(flow)
    } else {
      outputForFlowControl.write(frame.toByteArray())
      outputForFlowControl.flush()
    }
  }

  fun getOutputStream(): OutputStream = outputForFlowControl

  fun getInputStream(): InputStream = inputForFlowControl
}
