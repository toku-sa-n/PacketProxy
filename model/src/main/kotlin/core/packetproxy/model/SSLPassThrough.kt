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

@DatabaseTable(tableName = "sslpassthroughs")
class SSLPassThrough {
  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField private var enabled: Boolean? = null

  @field:DatabaseField(uniqueCombo = true) private var server_name: String? = null

  @field:DatabaseField(uniqueCombo = true) private var listen_port = 0

  constructor()

  @Throws(Exception::class)
  constructor(server_name: String, listen_port: Int) {
    setEnabled()
    setServerName(server_name)
    setListenPort(listen_port)
  }

  fun isEnabled(): Boolean = this.enabled!!

  fun setEnabled() {
    this.enabled = true
  }

  fun setDisabled() {
    this.enabled = false
  }

  fun getServerName(): String? = this.server_name

  fun setServerName(server_name: String) {
    this.server_name = server_name
  }

  @Throws(Exception::class) fun getListenPort(): Int = listen_port

  @Throws(Exception::class)
  fun setListenPort(listen_port: Int) {
    this.listen_port = listen_port
  }

  fun getId(): Int = id

  fun setId(id: Int) {
    this.id = id
  }

  override fun hashCode(): Int = this.getId()

  fun equals(obj: SSLPassThrough): Boolean = if (this.getId() == obj.getId()) true else false

  companion object {
    const val ALL_PORTS = -1
  }
}
