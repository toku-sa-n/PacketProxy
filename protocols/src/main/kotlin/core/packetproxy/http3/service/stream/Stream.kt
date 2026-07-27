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

import packetproxy.http3.utils.messageStreamId
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId

abstract class Stream(@JvmField var streamId: StreamId, @JvmField var streamType: StreamType) {
  enum class StreamType(@JvmField val type: Long) {
    ControlStreamType(0x0),
    QpackEncoderStreamType(0x2),
    QpackDecoderStreamType(0x3),
    NoStreamType(0x4);

    fun getType(): Long = type

    companion object {
      @JvmStatic
      fun of(typeId: Int): StreamType? {
        for (streamType in entries) {
          if (streamType.type == typeId.toLong()) {
            return streamType
          }
        }
        return null
      }
    }
  }

  fun processable(streamId: StreamId): Boolean = this.streamId == streamId

  fun processable(msg: QuicMessage): Boolean = processable(msg.messageStreamId())

  fun streamTypeEquals(type: Long): Boolean = streamType.type == type
}
