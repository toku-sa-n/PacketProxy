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
package packetproxy.http3.utils

import java.nio.ByteBuffer
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId
import packetproxy.quic.value.VariableLengthInteger

internal fun VariableLengthInteger.longValue(): Long = value

internal fun readSimpleBytes(buffer: ByteBuffer, sizeOfBytes: Long): ByteArray {
  val bytes = ByteArray(sizeOfBytes.toInt())
  buffer.get(bytes)
  return bytes
}

internal fun parseVarInt(buffer: ByteBuffer): Long = VariableLengthInteger.parse(buffer).longValue()

internal fun StreamId.streamIdLong(): Long = id

internal fun QuicMessage.dataBytes(): ByteArray = data

internal fun QuicMessage.messageStreamId(): StreamId = streamId

internal fun quicMessageOf(streamId: StreamId, data: ByteArray): QuicMessage =
  QuicMessage.of(streamId, data)
