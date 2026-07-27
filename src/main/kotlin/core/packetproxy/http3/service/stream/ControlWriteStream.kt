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
import packetproxy.http3.utils.quicMessageOf
import packetproxy.http3.value.Setting
import packetproxy.http3.value.frame.SettingsFrame
import packetproxy.quic.value.QuicMessages
import packetproxy.quic.value.StreamId
import packetproxy.util.Logging.errWithStackTrace

open class ControlWriteStream(streamId: StreamId) :
  Stream(streamId, StreamType.ControlStreamType), WriteStream {
  private val buffer = ByteArrayOutputStream()

  init {
    try {
      buffer.write(byteArrayOf(streamType.type.toByte()))
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Synchronized
  fun write(setting: Setting) {
    write(SettingsFrame.of(setting).getBytes())
  }

  @Synchronized
  override fun write(data: ByteArray) {
    try {
      buffer.write(data)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Synchronized
  override fun readAllQuicMessages(): QuicMessages {
    val msgs = QuicMessages.emptyList()
    if (buffer.size() > 0) {
      msgs.add(quicMessageOf(streamId, buffer.toByteArray()))
      buffer.reset()
    }
    return msgs
  }
}
