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

class SettingsFrame : Frame {
  enum class SettingsFrameType {
    RESERVED,
    SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_ENABLE_PUSH,
    SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
  }

  private val values: MutableMap<SettingsFrameType, Int> = HashMap()

  @Throws(Exception::class) constructor(frame: Frame) : super(frame) { parsePayload() }
  @Throws(Exception::class) constructor(data: ByteArray) : super(data) { parsePayload() }

  @Throws(Exception::class)
  private fun parsePayload() {
    val bb = ByteBuffer.allocate(4096)
    bb.put(payload)
    bb.flip()
    val settingsFrameTypes = SettingsFrameType.entries.toTypedArray()
    var length = 0
    while (length < bb.limit()) {
      val l = bb.getShort()
      if (l in 0x00 until settingsFrameTypes.size) {
        val type = settingsFrameTypes[l.toInt()]
        val data = bb.getInt()
        values[type] = data
      }
      length += 6
    }
  }

  operator fun get(type: SettingsFrameType): Int =
    if (values.containsKey(type)) values[type]!! else defaultValues[type.ordinal]

  fun set(type: SettingsFrameType, value: Int) {
    values[type] = value
  }

  override fun toString(): String = super.toString() + values

  companion object {
    @JvmField val TYPE: Type = Type.SETTINGS
    private val defaultValues = intArrayOf(0, 4096, 1, 10, 65535, 16884, 65536)
  }
}
