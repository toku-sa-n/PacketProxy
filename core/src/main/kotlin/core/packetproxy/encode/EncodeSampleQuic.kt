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
package packetproxy.encode

import java.nio.ByteBuffer
import packetproxy.model.Packet
import packetproxy.quic.value.QuicMessages
import packetproxy.quic.value.StreamId

class EncodeSampleQuic(ALPN: String?) : Encoder(ALPN) {
  override fun getName(): String = "Sample Quic"

  /* 1つのリクエスト/レスポンスのサイズで区切ってください */
  @Throws(Exception::class)
  override fun checkDelimiter(input_data: ByteArray): Int {
    val buffer = ByteBuffer.wrap(input_data)
    buffer.getLong()
    val length = buffer.getLong()
    return (8 + 8 + length).toInt()
  }

  @Throws(Exception::class)
  override fun decodeClientRequest(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class)
  override fun encodeClientRequest(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class)
  override fun decodeServerResponse(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class)
  override fun encodeServerResponse(input_data: ByteArray): ByteArray = input_data

  private fun getSummary(packet: Packet): String {
    val messages = QuicMessages.parse(packet.getDecodedData())
    if (messages.size() > 0) {
      val msg = messages[0]
      val streamId = msg.streamId
      val direction = if (streamId.isBidirectional()) "[Bi]" else "[Uni]"
      var http3Info = ""
      if (listOf(StreamId.of(0x02L), StreamId.of(0x03L)).any { id -> id == streamId }) {
        http3Info = "HTTP3 Setting"
      } else if (listOf(StreamId.of(0x06L), StreamId.of(0x07L)).any { id -> id == streamId }) {
        http3Info = "HTTP3 QPACK Encoder"
      } else if (listOf(StreamId.of(0x0aL), StreamId.of(0x0bL)).any { id -> id == streamId }) {
        http3Info = "HTTP3 QPACK Decoder"
      }
      return String.format("%s %s %s", streamId, http3Info, direction)
    }
    return "Unknown QuicMessage"
  }

  override fun getSummarizedResponse(packet: Packet): String = getSummary(packet)

  override fun getSummarizedRequest(packet: Packet): String = getSummary(packet)
}
