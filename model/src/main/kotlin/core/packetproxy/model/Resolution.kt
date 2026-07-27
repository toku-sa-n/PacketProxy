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

@DatabaseTable(tableName = "resolutions")
class Resolution {
  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField(uniqueCombo = true) private var ip: String? = null

  @field:DatabaseField(uniqueCombo = true) private var hostname: String? = null

  @field:DatabaseField private var enabled = false

  @field:DatabaseField private var comment: String? = null

  constructor()

  constructor(ip: String, hostname: String) {
    initialize(ip, hostname, false, "")
  }

  constructor(ip: String, hostname: String, enabled: Boolean, comment: String) {
    initialize(ip, hostname, enabled, comment)
  }

  private fun initialize(ip: String, hostname: String, enabled: Boolean, comment: String) {
    this.ip = ip
    this.hostname = hostname
    this.enabled = enabled
    this.comment = comment
  }

  override fun toString(): String = String.format("%s to %s", ip, hostname)

  fun getId(): Int = this.id

  fun setId(id: Int) {
    this.id = id
  }

  fun getIp(): String? = this.ip

  fun setIp(ip: String) {
    this.ip = ip
  }

  fun getHostName(): String? = hostname

  fun setHostName(hostname: String) {
    this.hostname = hostname
  }

  fun enableResolution() {
    this.enabled = true
  }

  fun disableResolution() {
    this.enabled = false
  }

  fun isEnabled(): Boolean = this.enabled

  fun setEnabled(enabled: Boolean) {
    this.enabled = enabled
  }

  fun getComment(): String? = this.comment

  fun setComment(comment: String) {
    this.comment = comment
  }
}
