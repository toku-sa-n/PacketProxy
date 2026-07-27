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
import java.util.Optional
import org.apache.commons.lang3.ArrayUtils
import packetproxy.http3.service.frame.FrameParser
import packetproxy.http3.utils.dataBytes
import packetproxy.http3.value.Setting
import packetproxy.http3.value.frame.Frames
import packetproxy.http3.value.frame.GreaseFrame
import packetproxy.http3.value.frame.SettingsFrame
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId
import packetproxy.util.Throwing.rethrow

open class ControlReadStream(streamId: StreamId) :
  Stream(streamId, StreamType.ControlStreamType), ReadStream {
  private var hasWrite = false
  private val frames = Frames.emptyList()
  private var setting: Setting? = null

  @Throws(Exception::class)
  override fun write(msg: QuicMessage) {
    var targetData = msg.dataBytes()
    if (!hasWrite) {
      if (!streamTypeEquals(targetData[0].toLong())) {
        throw Exception(
          String.format(
            "Error: Not start with %x on http3 control stream. (actual: %x)",
            streamType.type,
            targetData[0],
          )
        )
      }
      targetData = ArrayUtils.subarray(targetData, 1, targetData.size)
      hasWrite = true
    }
    val parsed = FrameParser.parse(targetData)
    parsed.forEach(
      rethrow { frame ->
        when (frame) {
          is SettingsFrame -> setting = frame.getSetting()
          is GreaseFrame -> {
            /* ignored */
          }
          else ->
            throw Exception(
              String.format("Error: add non-SettingsFrame into ControlStream: %s", frame)
            )
        }
        frames.add(frame)
      }
    )
  }

  override fun readAllBytes(): ByteArray {
    val bytes = ByteArrayOutputStream()
    frames.forEach(rethrow { frame -> bytes.write(frame.getBytes()) })
    frames.clear()
    return bytes.toByteArray()
  }

  fun getSetting(): Optional<Setting> =
    if (setting != null) Optional.of(setting!!) else Optional.empty()
}
