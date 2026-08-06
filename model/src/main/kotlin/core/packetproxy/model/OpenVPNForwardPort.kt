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
package packetproxy.model

import com.j256.ormlite.field.DatabaseField
import com.j256.ormlite.table.DatabaseTable

@DatabaseTable(tableName = "openvpn_forward_ports")
class OpenVPNForwardPort {
  enum class TYPE(private val proto: String) {
    TCP("tcp"),
    UDP("udp");

    override fun toString(): String = this.proto
  }

  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField(uniqueCombo = true) private var type: TYPE? = null

  @field:DatabaseField(uniqueCombo = true) private var fromPort = 0

  @field:DatabaseField(uniqueCombo = true) private var toPort = 0

  constructor()

  constructor(type: TYPE, fromPort: Int, toPort: Int) {
    this.type = type
    this.fromPort = fromPort
    this.toPort = toPort
  }

  fun setId(id: Int) {
    this.id = id
  }

  fun getId(): Int = this.id

  fun setType(type: TYPE) {
    this.type = type
  }

  fun getType(): TYPE? = this.type

  fun setFromPort(fromPort: Int) {
    this.fromPort = fromPort
  }

  fun getFromPort(): Int = this.fromPort

  fun setToPort(toPort: Int) {
    this.toPort = toPort
  }

  fun getToPort(): Int = this.toPort

  override fun hashCode(): Int = this.getId()

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is OpenVPNForwardPort) return false
    return this.getId() == other.getId()
  }
}
