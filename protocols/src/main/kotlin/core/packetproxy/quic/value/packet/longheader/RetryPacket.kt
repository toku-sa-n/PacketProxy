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

package packetproxy.quic.value.packet.longheader

import java.nio.ByteBuffer
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.VariableLengthInteger

class RetryPacket : LongHeaderPacket {
  val token: ByteArray
  val tag: ByteArray

  constructor(buffer: ByteBuffer) : super(buffer) {
    val length = VariableLengthInteger.parse(buffer).value
    token = SimpleBytes.parse(buffer, length.toInt()).bytes
    tag = SimpleBytes.parse(buffer, 16).bytes
  }

  constructor(
    type: Byte,
    version: Int,
    connIdPair: ConnectionIdPair,
    token: ByteArray,
    tag: ByteArray,
  ) : super(type, version, connIdPair) {
    this.token = token
    this.tag = tag
  }

  companion object {
    @JvmStatic fun `is`(type: Byte): Boolean = (type.toInt() and 0xf0) == 0xf0
  }
}
