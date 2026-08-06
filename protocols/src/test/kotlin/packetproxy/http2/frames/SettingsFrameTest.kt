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
package packetproxy.http2.frames

import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import packetproxy.http2.frames.SettingsFrame.SettingsFrameType
import packetproxy.util.Logging

class SettingsFrameTest {
  @Test
  @Throws(Exception::class)
  fun smoke() {
    val data = Hex.decodeHex("000012040000000000000300000064000400100000000600004000".toCharArray())
    val sf = SettingsFrame(data)
    Logging.log(sf)
  }

  @Test
  @Throws(Exception::class)
  fun defaultMaxFrameSizeIs16384() {
    val empty = Frame(SettingsFrame.TYPE, 0, 0, ByteArray(0))
    val sf = SettingsFrame(empty)
    assertThat(sf[SettingsFrameType.SETTINGS_MAX_FRAME_SIZE]).isEqualTo(16384)
  }

  @Test
  @Throws(Exception::class)
  fun unknownSettingIdStillConsumesValue() {
    // length=12: unknown id 0x0099 + value, then known ENABLE_PUSH=0
    val payload = ByteBuffer.allocate(12)
    payload.putShort(0x0099.toShort())
    payload.putInt(0x12345678)
    payload.putShort(SettingsFrameType.SETTINGS_ENABLE_PUSH.ordinal.toShort())
    payload.putInt(0)
    val frameBytes = ByteBuffer.allocate(9 + 12)
    frameBytes.put(((12 ushr 16) and 0xff).toByte())
    frameBytes.put(((12 ushr 8) and 0xff).toByte())
    frameBytes.put((12 and 0xff).toByte())
    frameBytes.put(SettingsFrame.TYPE.ordinal.toByte())
    frameBytes.put(0)
    frameBytes.putInt(0)
    frameBytes.put(payload.array())
    val sf = SettingsFrame(frameBytes.array())
    assertThat(sf[SettingsFrameType.SETTINGS_ENABLE_PUSH]).isEqualTo(0)
  }
}
