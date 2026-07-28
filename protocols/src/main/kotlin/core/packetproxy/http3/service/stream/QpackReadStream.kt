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
import org.apache.commons.lang3.ArrayUtils
import packetproxy.http3.utils.dataBytes
import packetproxy.http3.value.frame.Frames
import packetproxy.http3.value.frame.RawFrame
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId
import packetproxy.util.rethrow

open class QpackReadStream(streamId: StreamId, streamType: StreamType) :
  Stream(streamId, streamType), ReadStream {
  private var hasWrite = false
  private val frames = Frames.emptyList()

  @Synchronized
  @Throws(Exception::class)
  override fun write(msg: QuicMessage) {
    var targetData = msg.dataBytes()
    if (!hasWrite) {
      if (!streamTypeEquals(targetData[0].toLong())) {
        throw Exception(
          String.format(
            "QpackStream.java: Error: Not start with %x. (actual: %x)",
            streamType.type,
            targetData[0],
          )
        )
      }
      targetData = ArrayUtils.subarray(targetData, 1, targetData.size)
      hasWrite = true
    }
    if (targetData.isNotEmpty()) {
      frames.add(RawFrame.of(targetData))
    }
  }

  @Synchronized
  override fun readAllBytes(): ByteArray {
    val bytes = ByteArrayOutputStream()
    frames.forEach(rethrow { frame -> bytes.write(frame.getBytes()) })
    frames.clear()
    return bytes.toByteArray()
  }
}
