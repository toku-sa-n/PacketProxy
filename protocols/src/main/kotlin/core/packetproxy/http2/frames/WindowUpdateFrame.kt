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

open class WindowUpdateFrame : Frame {
  private var window: Int = 0

  @Throws(Exception::class)
  constructor(frame: Frame) : super(frame) {
    parsePayload()
  }

  @Throws(Exception::class)
  constructor(data: ByteArray) : super(data) {
    parsePayload()
  }

  @Throws(Exception::class)
  private fun parsePayload() {
    window =
      ((payload[0].toInt() and 0x7f) shl
        24 or
        ((payload[1].toInt() and 0xff) shl 16) or
        ((payload[2].toInt() and 0xff) shl 8) or
        (payload[3].toInt() and 0xff))
  }

  fun getWindowSize(): Int = window

  override fun toString(): String = super.toString() + window.toString()

  companion object {
    @JvmField val TYPE: Type = Type.WINDOW_UPDATE
  }
}
