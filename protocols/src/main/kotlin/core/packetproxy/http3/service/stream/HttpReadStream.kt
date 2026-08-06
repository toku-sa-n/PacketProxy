/*
 * Copyright 2023 DeNA Co., Ltd.
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
package packetproxy.http3.service.stream

import java.io.ByteArrayOutputStream
import packetproxy.http3.service.HttpRaw
import packetproxy.http3.service.frame.FrameParser
import packetproxy.http3.utils.dataBytes
import packetproxy.http3.value.frame.DataFrame
import packetproxy.http3.value.frame.Frame
import packetproxy.http3.value.frame.GreaseFrame
import packetproxy.http3.value.frame.HeadersFrame
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId
import packetproxy.util.log
import packetproxy.util.rethrow

open class HttpReadStream(streamId: StreamId) :
  Stream(streamId, StreamType.NoStreamType), ReadStream {
  private val headers = ByteArrayOutputStream()
  private val data = ByteArrayOutputStream()
  private var messageComplete = false

  @Throws(Exception::class)
  fun write(frame: Frame) {
    when (frame) {
      is HeadersFrame -> {
        headers.write(frame.getData())
        return
      }
      is DataFrame -> {
        data.write(frame.getData())
        return
      }
      is GreaseFrame -> {
        log(frame.toString())
        return
      }
      else ->
        throw Exception(
          "Error: write UnknownFrame(neither HeaderFrame nor DataFrame) to HttpStream."
        )
    }
  }

  @Throws(Exception::class)
  override fun write(msg: QuicMessage) {
    val frames = FrameParser.parse(msg.dataBytes())
    frames.forEach(rethrow { write(it) })
    // QuicMessage for bidirectional HTTP streams is delivered only after STREAM FIN
    messageComplete = true
  }

  override fun readAllBytes(): ByteArray = byteArrayOf()

  fun readHeaderBytes(): ByteArray = headers.toByteArray()

  fun readDataBytes(): ByteArray = data.toByteArray()

  fun readHttpRaw(): HttpRaw = HttpRaw.of(streamId, readHeaderBytes(), readDataBytes())

  fun isEmpty(): Boolean = headers.size() == 0

  /** Ready when headers arrived and the QUIC stream message is complete (FIN observed). */
  fun isReady(): Boolean = !isEmpty() && messageComplete
}
