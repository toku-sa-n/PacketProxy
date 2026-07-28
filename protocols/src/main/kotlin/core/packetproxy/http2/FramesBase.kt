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
import org.eclipse.jetty.http2.hpack.HpackDecoder
import org.eclipse.jetty.http2.hpack.HpackEncoder
import packetproxy.http2.frames.*
import packetproxy.http2.frames.Frame
import packetproxy.model.Packet

abstract class FramesBase {
  protected var clientFrameManager = FrameManager()
  protected var serverFrameManager = FrameManager()
  protected var alreadySentClientRequestPrologue = false
  protected var alreadySentClientRequestEpilogue = false
  private val streamIdRemapper = StreamIdRemapper()

  @Throws(Exception::class)
  constructor() {
    clientFrameManager = FrameManager()
    serverFrameManager = FrameManager()
    serverFrameManager.setStreamIdRemapper(streamIdRemapper)
  }

  open fun getName(): String = "HTTP2 Frames Base"

  @Throws(Exception::class)
  fun checkDelimiter(data: ByteArray): Int = packetproxy.http2.frames.checkDelimiter(data)

  @Throws(Exception::class)
  fun clientRequestArrived(frames: ByteArray) {
    clientFrameManager.write(frames)
  }

  @Throws(Exception::class)
  fun serverResponseArrived(frames: ByteArray) {
    serverFrameManager.write(streamIdRemapper.rewriteResponseToClient(frames))
  }

  @Throws(Exception::class)
  open fun passThroughClientRequest(): ByteArray {
    val out = ByteArrayOutputStream()
    if (!alreadySentClientRequestPrologue) {
      out.write(PREFACE)
      out.write(SETTINGS)
      out.write(WINDOW_UPDATE)
      alreadySentClientRequestPrologue = true
    }
    for (frame in clientFrameManager.readControlFrames()) {
      out.write(frame.toByteArray())
    }
    return out.toByteArray()
  }

  @Throws(Exception::class)
  open fun passThroughServerResponse(): ByteArray {
    val out = ByteArrayOutputStream()
    if (!alreadySentClientRequestEpilogue) {
      out.write(SETTINGS)
      out.write(WINDOW_UPDATE)
      alreadySentClientRequestEpilogue = true
    }
    for (frame in serverFrameManager.readControlFrames()) {
      out.write(frame.toByteArray())
    }
    return out.toByteArray()
  }

  @Throws(Exception::class)
  fun clientRequestAvailable(): ByteArray? {
    val frames = clientFrameManager.readHeadersDataFrames()
    return passFramesToDecodeClientRequest(frames)
  }

  @Throws(Exception::class)
  fun serverResponseAvailable(): ByteArray? {
    val frames = serverFrameManager.readHeadersDataFrames()
    return passFramesToDecodeServerResponse(frames)
  }

  @Throws(Exception::class)
  fun decodeClientRequest(frames: ByteArray): ByteArray = decodeClientRequestFromFrames(frames)

  @Throws(Exception::class)
  fun encodeClientRequest(data: ByteArray): ByteArray = encodeClientRequestToFrames(data)

  @Throws(Exception::class)
  fun decodeServerResponse(frames: ByteArray): ByteArray = decodeServerResponseFromFrames(frames)

  @Throws(Exception::class)
  fun encodeServerResponse(data: ByteArray): ByteArray =
    encodeServerResponseToFrames(data) ?: byteArrayOf()

  @Throws(Exception::class)
  fun putToClientFlowControlledQueue(frames: ByteArray) {
    clientFrameManager.putToFlowControlledQueue(frames)
  }

  @Throws(Exception::class)
  fun putToServerFlowControlledQueue(frames: ByteArray) {
    serverFrameManager.putToFlowControlledQueue(frames)
  }

  @Throws(Exception::class)
  fun closeClientFlowControlledQueue() {
    clientFrameManager.closeFlowControlledQueue()
  }

  @Throws(Exception::class)
  fun closeServerFlowControlledQueue() {
    serverFrameManager.closeFlowControlledQueue()
  }

  fun getClientFlowControlledInputStream(): InputStream =
    clientFrameManager.getFlowControlledInputStream()

  fun getServerFlowControlledInputStream(): InputStream =
    serverFrameManager.getFlowControlledInputStream()

  protected fun getClientHpackDecoder(): HpackDecoder? = clientFrameManager.getHpackDecoder()

  protected fun getClientHpackEncoder(): HpackEncoder = clientFrameManager.getHpackEncoder()

  protected fun getServerHpackDecoder(): HpackDecoder? = serverFrameManager.getHpackDecoder()

  protected fun getServerHpackEncoder(): HpackEncoder = serverFrameManager.getHpackEncoder()

  @Throws(Exception::class)
  protected abstract fun passFramesToDecodeClientRequest(frames: List<Frame>): ByteArray?

  @Throws(Exception::class)
  protected abstract fun passFramesToDecodeServerResponse(frames: List<Frame>): ByteArray?

  @Throws(Exception::class)
  protected abstract fun decodeClientRequestFromFrames(frames: ByteArray): ByteArray

  @Throws(Exception::class)
  protected abstract fun decodeServerResponseFromFrames(frames: ByteArray): ByteArray

  @Throws(Exception::class)
  protected abstract fun encodeClientRequestToFrames(data: ByteArray): ByteArray

  @Throws(Exception::class)
  protected abstract fun encodeServerResponseToFrames(data: ByteArray): ByteArray?

  @Throws(Exception::class) abstract fun setGroupId(packet: Packet)
}
