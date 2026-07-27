/*
 * Copyright 2025 DeNA Co., Ltd.
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
package packetproxy.controller

import java.io.ByteArrayOutputStream
import packetproxy.DuplexFactory
import packetproxy.DuplexSync
import packetproxy.EncoderManager
import packetproxy.http2.frames.DataFrame
import packetproxy.http2.frames.Frame
import packetproxy.http2.frames.FrameUtils
import packetproxy.http2.frames.FrameUtils.PREFACE
import packetproxy.http2.frames.FrameUtils.SETTINGS
import packetproxy.http2.frames.FrameUtils.WINDOW_UPDATE
import packetproxy.http2.frames.HeadersFrame
import packetproxy.model.OneShotPacket
import packetproxy.model.Packet

class SinglePacketAttackController
@JvmOverloads
@Throws(Exception::class)
constructor(oneshot: OneShotPacket?, private val sleepTimeMs: Int = 100) {
  private val attackConnection: DuplexSync
  private val baseAttackFrames: AttackFrames

  init {
    var targetPacket = requireNotNull(oneshot) { "OneShotPacket cannot be null" }
    require(isHttp2(targetPacket)) { "Only HTTP/2 requests are supported for Single Packet Attack" }
    require(isRequest(targetPacket)) {
      "Only client requests are supported for Single Packet Attack"
    }
    require(!isGetMethod(targetPacket)) {
      "GET requests are not supported by Single Packet Attack because they cannot have DATA frames in HTTP/2."
    }

    attackConnection = DuplexFactory.createDuplexSyncForSinglePacketAttack(targetPacket)
    baseAttackFrames = generateAttackFrames(targetPacket)
  }

  @Throws(Exception::class)
  fun attack(count: Int) {
    if (count <= 0) {
      return
    }

    sendConnectionPreface()
    launchAttack(count)
  }

  @Throws(Exception::class)
  private fun sendConnectionPreface() {
    var preface = ByteArrayOutputStream()
    preface.write(PREFACE)
    preface.write(SETTINGS)
    preface.write(WINDOW_UPDATE)

    attackConnection.execFastSend(preface.toByteArray())
  }

  @Throws(Exception::class)
  private fun launchAttack(count: Int) {
    var requests = createRequests(count)

    for (request in requests) {
      request.sendFirstFrames()
    }

    Thread.sleep(sleepTimeMs.toLong())
    sendPing()

    var allLastFramesData = ByteArrayOutputStream()
    for (request in requests) {
      allLastFramesData.write(request.lastFramesData)
    }
    attackConnection.execFastSend(allLastFramesData.toByteArray())

    for (i in requests.indices) {
      attackConnection.receive()
    }
  }

  @Throws(Exception::class)
  private fun createRequests(count: Int): ArrayList<SingleAttackRequest> {
    var requests = ArrayList<SingleAttackRequest>()

    for (i in 0 until count) {
      var streamId = i * 2 + 1
      var request = SingleAttackRequest(streamId, baseAttackFrames, attackConnection)
      requests.add(request)
    }

    return requests
  }

  @Throws(Exception::class)
  private fun sendPing() {
    var pingPayload = ByteArray(8)
    var pingFrame = Frame(Frame.Type.PING, 0, 0, pingPayload)
    var pingData = pingFrame.toByteArray()
    attackConnection.execFastSend(pingData)
  }

  private class CategorizedFrames(frames: List<Frame>) {
    val headersFrames = ArrayList<HeadersFrame>()
    val dataFrames = ArrayList<DataFrame>()
    val otherFrames = ArrayList<Frame>()

    init {
      var filteredFrames = filterOutEmptyDataFrames(frames)
      categorizeFrames(filteredFrames)
      assertSameStreamId(filteredFrames)
    }

    fun getStreamId(): Int =
      when {
        headersFrames.isNotEmpty() -> headersFrames[0].streamId
        dataFrames.isNotEmpty() -> dataFrames[0].streamId
        otherFrames.isNotEmpty() -> otherFrames[0].streamId
        else -> throw IllegalStateException("No frames available to get stream ID")
      }

    private fun categorizeFrames(frames: List<Frame>) {
      for (frame in frames) {
        when (frame) {
          is HeadersFrame -> headersFrames.add(frame)
          is DataFrame -> dataFrames.add(frame)
          else -> otherFrames.add(frame)
        }
      }
    }

    private fun assertSameStreamId(frames: List<Frame>) {
      if (frames.isEmpty()) {
        throw IllegalStateException("No frames found to determine stream ID")
      }

      var expectedStreamId = frames[0].streamId
      for (frame in frames) {
        if (frame.streamId != expectedStreamId) {
          throw IllegalStateException(
            String.format(
              "Frame has different stream ID: expected %d, got %d (frame type: %s)",
              expectedStreamId,
              frame.streamId,
              frame.javaClass.simpleName,
            )
          )
        }
      }
    }
  }

  private class AttackFrames {
    val firstFrames: MutableList<Frame>
    val lastFrames: MutableList<Frame>

    @Throws(Exception::class)
    constructor(categorized: CategorizedFrames) {
      firstFrames = ArrayList()
      lastFrames = ArrayList()

      if (categorized.dataFrames.isNotEmpty()) {
        createWithBody(categorized)
      } else {
        createWithoutBody(categorized)
      }
    }

    constructor(firstFrames: List<Frame>, lastFrames: List<Frame>) {
      this.firstFrames = ArrayList(firstFrames)
      this.lastFrames = ArrayList(lastFrames)
    }

    @Throws(Exception::class)
    private fun createWithBody(categorized: CategorizedFrames) {
      processHeadersAndOtherFrames(categorized)

      var dataFrames = categorized.dataFrames
      if (dataFrames.isEmpty()) {
        throw IllegalStateException("No DATA frames found for request with body")
      }

      processDataFramesExceptLast(dataFrames)
      processLastDataFrame(dataFrames.last())
    }

    @Throws(Exception::class)
    private fun createWithoutBody(categorized: CategorizedFrames) {
      if (categorized.dataFrames.isNotEmpty()) {
        throw IllegalStateException("DATA frames found for request without body")
      }

      var streamId = categorized.getStreamId()
      processHeadersAndOtherFrames(categorized)

      lastFrames.add(DataFrame(DataFrame.FLAG_END_STREAM.toInt(), streamId, byteArrayOf()))
    }

    @Throws(Exception::class)
    private fun processHeadersAndOtherFrames(categorized: CategorizedFrames) {
      for (headersFrame in categorized.headersFrames) {
        var modifiedHeadersFrame = HeadersFrame(headersFrame.toByteArray(), null)
        modifiedHeadersFrame.flags =
          modifiedHeadersFrame.flags and HeadersFrame.FLAG_END_STREAM.toInt().inv()
        firstFrames.add(modifiedHeadersFrame)
      }

      firstFrames.addAll(categorized.otherFrames)
    }

    private fun processDataFramesExceptLast(dataFrames: List<DataFrame>) {
      for (i in 0 until dataFrames.size - 1) {
        var dataFrame = dataFrames[i]
        var modifiedDataFrame =
          DataFrame(
            dataFrame.flags and DataFrame.FLAG_END_STREAM.toInt().inv(),
            dataFrame.streamId,
            dataFrame.payload,
          )
        firstFrames.add(modifiedDataFrame)
      }
    }

    private fun processLastDataFrame(lastDataFrame: DataFrame) {
      var lastPayload = lastDataFrame.payload

      when (lastPayload.size) {
        0 -> throw IllegalStateException("Last DATA frame has no payload, which is not allowed")
        1 ->
          lastFrames.add(
            DataFrame(
              DataFrame.FLAG_END_STREAM.toInt(),
              lastDataFrame.streamId,
              byteArrayOf(lastPayload[0]),
            )
          )
        else -> splitLastDataFrame(lastDataFrame)
      }
    }

    private fun splitLastDataFrame(lastDataFrame: DataFrame) {
      var lastPayload = lastDataFrame.payload
      if (lastPayload.size <= 1) {
        throw IllegalStateException(
          "Last DATA frame has no payload or only one byte, which is not allowed"
        )
      }

      var payloadExceptLast = lastPayload.copyOf(lastPayload.size - 1)
      var firstPartDataFrame =
        DataFrame(
          lastDataFrame.flags and DataFrame.FLAG_END_STREAM.toInt().inv(),
          lastDataFrame.streamId,
          payloadExceptLast,
        )
      firstFrames.add(firstPartDataFrame)

      var finalDataFrame =
        DataFrame(
          DataFrame.FLAG_END_STREAM.toInt(),
          lastDataFrame.streamId,
          byteArrayOf(lastPayload.last()),
        )
      lastFrames.add(finalDataFrame)
    }
  }

  private class SingleAttackRequest(
    private val streamId: Int,
    private val originalAttackFrames: AttackFrames,
    private val connection: DuplexSync,
  ) {
    private val streamAttackFrames = createStreamAttackFrames()

    @Throws(Exception::class)
    fun sendFirstFrames() {
      var firstFramesData = FrameUtils.toByteArray(streamAttackFrames.firstFrames)
      connection.execFastSend(firstFramesData)
    }

    @get:Throws(Exception::class)
    val lastFramesData: ByteArray
      get() = FrameUtils.toByteArray(streamAttackFrames.lastFrames)

    @Throws(Exception::class)
    private fun createStreamAttackFrames(): AttackFrames {
      var newFirstFrames = updateFrameStreamIds(originalAttackFrames.firstFrames, streamId)
      var newLastFrames = updateFrameStreamIds(originalAttackFrames.lastFrames, streamId)
      return AttackFrames(newFirstFrames, newLastFrames)
    }

    @Throws(Exception::class)
    private fun updateFrameStreamIds(originalFrames: List<Frame>, newStreamId: Int): List<Frame> {
      var updatedFrames = ArrayList<Frame>()

      for (frame in originalFrames) {
        var clonedFrame = Frame(frame)
        clonedFrame.streamId = newStreamId
        updatedFrames.add(clonedFrame)
      }

      return updatedFrames
    }
  }

  companion object {
    private fun isHttp2(oneshot: OneShotPacket): Boolean {
      var alpn = oneshot.getAlpn()
      return alpn != null && (alpn == "h2" || alpn == "grpc" || alpn == "grpc-exp")
    }

    private fun isRequest(oneshot: OneShotPacket): Boolean =
      oneshot.getDirection() == Packet.Direction.CLIENT

    private fun isGetMethod(oneshot: OneShotPacket): Boolean {
      var httpText = String(oneshot.getData())
      var lines = httpText.split(Regex("\\r?\\n"))
      if (lines.isEmpty()) {
        return false
      }

      var parts = lines[0].split(" ")
      if (parts.isEmpty()) {
        return false
      }

      return parts[0].uppercase() == "GET"
    }

    @Throws(Exception::class)
    private fun generateAttackFrames(packet: OneShotPacket): AttackFrames {
      var originalFrames = convertPacketToFrames(packet)
      if (originalFrames.isEmpty()) {
        throw IllegalArgumentException("No frames found after encoding and parsing")
      }

      return AttackFrames(CategorizedFrames(originalFrames))
    }

    @Throws(Exception::class)
    private fun convertPacketToFrames(packet: OneShotPacket): List<Frame> {
      var encoder =
        EncoderManager.getInstance().createInstance(packet.getEncoder()!!, packet.getAlpn())
      checkNotNull(encoder) { "Could not create encoder for target packet" }

      var binaryFrames = encoder.encodeClientRequest(packet.getData())
      return FrameUtils.parseFrames(binaryFrames)
    }

    private fun filterOutEmptyDataFrames(frames: List<Frame>): List<Frame> =
      frames.filter { frame -> frame !is DataFrame || frame.payload.isNotEmpty() }
  }
}
