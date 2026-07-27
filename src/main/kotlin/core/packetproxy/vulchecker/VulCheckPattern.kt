/*
 * Copyright 2021 DeNA Co., Ltd.
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
package packetproxy.vulchecker

import packetproxy.common.Range
import packetproxy.model.OneShotPacket

class VulCheckPattern(
  private val name: String,
  private val packet: OneShotPacket,
  private val range: Range?,
) {
  fun getName(): String = name

  fun getPacket(): OneShotPacket = packet

  fun getRange(): Range? = range

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is VulCheckPattern) return false
    return name == other.getName() && packet == other.packet && range == other.range
  }

  override fun hashCode(): Int {
    var result = name.hashCode()
    result = 31 * result + packet.hashCode()
    result = 31 * result + (range?.hashCode() ?: 0)
    return result
  }

  override fun toString(): String = "VulCheckPattern(name=$name, packet=$packet, range=$range)"
}
