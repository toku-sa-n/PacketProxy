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
package packetproxy.quic.value

import java.nio.ByteBuffer

data class StreamId(val id: Long) {

  fun getBytes(): ByteArray = ByteBuffer.allocate(8).putLong(id).array()

  fun isClientInitiated(): Boolean = (id and 0x01L) == 0L

  fun isServerInitiated(): Boolean = (id and 0x01L) > 0L

  fun isUniDirectional(): Boolean = (id and 0x02L) > 0L

  fun isBidirectional(): Boolean = (id and 0x02L) == 0L

  override fun toString(): String = String.format("StreamId(%x)", id)

  companion object {
    @JvmStatic fun of(id: Long): StreamId = StreamId(id)

    @JvmStatic fun parse(buffer: ByteBuffer): StreamId = of(buffer.getLong())
  }
}
