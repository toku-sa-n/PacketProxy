/*
 * Copyright 2022 DeNA Co., Ltd.
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
package packetproxy.http3.service

import java.util.Optional
import java.util.concurrent.atomic.AtomicReference
import packetproxy.http3.service.stream.ControlReadStream
import packetproxy.http3.service.stream.HttpReadStream
import packetproxy.http3.service.stream.QpackReadStream
import packetproxy.http3.service.stream.Stream
import packetproxy.http3.utils.dataBytes
import packetproxy.http3.utils.messageStreamId
import packetproxy.http3.value.Setting
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.QuicMessages
import packetproxy.quic.value.StreamId
import packetproxy.util.Throwing.rethrow

open class StreamsReader(role: Constants.Role) {
  private val httpStreams: MutableMap<StreamId, HttpReadStream> = HashMap()
  private val controlReadStream: ControlReadStream =
    if (role == Constants.Role.CLIENT) {
      ControlReadStream(StreamId.of(0x2))
    } else {
      ControlReadStream(StreamId.of(0x3))
    }

  private var qpackEncodeStreamReader: QpackReadStream? = null
  private var qpackDecodeStreamReader: QpackReadStream? = null

  @Throws(Exception::class)
  private fun writeQpackMsg(msg: QuicMessage) {
    qpackEncodeStreamReader?.let {
      if (it.processable(msg)) {
        it.write(msg)
        return
      }
    }
    qpackDecodeStreamReader?.let {
      if (it.processable(msg)) {
        it.write(msg)
        return
      }
    }
    val data = msg.dataBytes()
    if (data.isEmpty()) {
      return
    }
    val streamType = Stream.StreamType.of(data[0].toInt())
    when (streamType) {
      Stream.StreamType.QpackEncoderStreamType -> {
        qpackEncodeStreamReader =
          QpackReadStream(msg.messageStreamId(), Stream.StreamType.QpackEncoderStreamType)
        qpackEncodeStreamReader!!.write(msg)
        return
      }
      Stream.StreamType.QpackDecoderStreamType -> {
        qpackDecodeStreamReader =
          QpackReadStream(msg.messageStreamId(), Stream.StreamType.QpackDecoderStreamType)
        qpackDecodeStreamReader!!.write(msg)
      }
      else -> throw Exception("QPackStreamType is neither QpackEncoder(0x2) nor QpackDecoder(0x3)")
    }
  }

  @Synchronized
  @Throws(Exception::class)
  fun write(msg: QuicMessage) {
    if (controlReadStream.processable(msg)) {
      controlReadStream.write(msg)
      return
    }

    if (msg.messageStreamId().isUniDirectional()) {
      writeQpackMsg(msg)
      return
    }

    val sid = msg.messageStreamId()
    if (!httpStreams.containsKey(sid)) {
      httpStreams[sid] = HttpReadStream(sid)
    }
    httpStreams[sid]!!.write(msg)
  }

  @Synchronized
  fun write(msgs: QuicMessages) {
    msgs.forEach(rethrow { write(it) })
  }

  @Synchronized fun getSetting(): Optional<Setting> = controlReadStream.getSetting()

  @Synchronized
  fun readQpackEncodeData(): ByteArray = qpackEncodeStreamReader?.readAllBytes() ?: byteArrayOf()

  @Synchronized
  fun readQpackDecodeData(): ByteArray = qpackDecodeStreamReader?.readAllBytes() ?: byteArrayOf()

  fun readHttpRaw(): Optional<HttpRaw> {
    val httpRaw = AtomicReference<Optional<HttpRaw>>(Optional.empty())
    httpStreams.entries
      .stream()
      .filter { ent -> ent.key.isBidirectional() }
      .filter { ent -> !ent.value.isEmpty() }
      .map { it.key }
      .findFirst()
      .ifPresent(
        rethrow { streamId ->
          val httpStreamReader = httpStreams[streamId]!!
          httpRaw.set(Optional.of(httpStreamReader.readHttpRaw()))
          httpStreams.remove(streamId)
        }
      )
    return httpRaw.get()
  }
}
