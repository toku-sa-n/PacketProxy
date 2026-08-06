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

import packetproxy.http3.service.stream.ControlWriteStream
import packetproxy.http3.service.stream.HttpWriteStreams
import packetproxy.http3.service.stream.QpackWriteStream
import packetproxy.http3.service.stream.Stream
import packetproxy.http3.value.Setting
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.QuicMessages
import packetproxy.quic.value.StreamId

open class StreamsWriter(role: Constants.Role) {
  private val httpWriteStreams = HttpWriteStreams()
  private val controlWriteStream: ControlWriteStream
  private val qpackEncodeStreamWriter: QpackWriteStream
  private val qpackDecodeStreamWriter: QpackWriteStream

  init {
    if (role == Constants.Role.CLIENT) {
      controlWriteStream = ControlWriteStream(StreamId.of(0x3))
      qpackEncodeStreamWriter =
        QpackWriteStream(StreamId.of(0x7), Stream.StreamType.QpackEncoderStreamType)
      qpackDecodeStreamWriter =
        QpackWriteStream(StreamId.of(0xb), Stream.StreamType.QpackDecoderStreamType)
    } else {
      controlWriteStream = ControlWriteStream(StreamId.of(0x2))
      qpackEncodeStreamWriter =
        QpackWriteStream(StreamId.of(0x6), Stream.StreamType.QpackEncoderStreamType)
      qpackDecodeStreamWriter =
        QpackWriteStream(StreamId.of(0xa), Stream.StreamType.QpackDecoderStreamType)
    }
  }

  @Synchronized
  fun writeSetting(setting: Setting) {
    controlWriteStream.write(setting)
  }

  @Synchronized
  @Throws(Exception::class)
  fun writeQpackEncodeData(data: ByteArray) {
    qpackEncodeStreamWriter.write(data)
  }

  @Synchronized
  @Throws(Exception::class)
  fun writeQpackDecodeData(data: ByteArray) {
    qpackDecodeStreamWriter.write(data)
  }

  @Synchronized
  @Throws(Exception::class)
  fun write(httpRaw: HttpRaw) {
    httpWriteStreams.write(httpRaw)
  }

  @Synchronized
  @Throws(Exception::class)
  fun readQuicMessages(): QuicMessages {
    val msgs = QuicMessages.emptyList()
    msgs.addAll(controlWriteStream.readAllQuicMessages())
    msgs.addAll(qpackEncodeStreamWriter.readAllQuicMessages())
    msgs.addAll(qpackDecodeStreamWriter.readAllQuicMessages())
    msgs.addAll(httpWriteStreams.readAllQuicMessages())
    return msgs
  }
}
