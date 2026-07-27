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

open class GoawayFrame : Frame {
  private var lastStreamId: Int = 0
  private var errorCode: Int = 0

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
    val bb = ByteBuffer.allocate(4096)
    bb.put(payload)
    bb.flip()
    lastStreamId = bb.getInt()
    errorCode = bb.getInt()
  }

  fun getLastStreamId(): Int = lastStreamId

  fun getErrorCode(): Int = errorCode

  override fun toString(): String =
    super.toString() + ", last stream id=" + lastStreamId + ",error code=" + errorCode

  companion object {
    @JvmField val TYPE: Type = Type.GOAWAY
  }
}
