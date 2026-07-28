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
import javax.swing.JComponent
import javax.swing.JMenuItem

@DatabaseTable(tableName = "extensions")
open class Extension {
  @field:DatabaseField(id = true) private var name: String? = null

  @field:DatabaseField private var enabled = false

  @field:DatabaseField private var path: String? = null

  constructor()

  @Throws(Exception::class)
  constructor(name: String, path: String) {
    setEnabled(false)
    setName(name)
    setPath(path)
  }

  fun isEnabled(): Boolean = this.enabled

  fun setEnabled(e: Boolean) {
    this.enabled = e
  }

  fun getName(): String? = this.name

  fun setName(s: String) {
    this.name = s
  }

  fun getPath(): String? = this.path

  fun setPath(s: String) {
    this.path = s
  }

  @Throws(Exception::class)
  open fun createPanel(): JComponent? {
    // Please override this
    return null
  }

  open fun historyClickHandler(): JMenuItem? {
    // Please override this
    return null
  }

  open fun historyClickHandler(packetProvider: () -> Packet): JMenuItem? = historyClickHandler()

  open fun getEncoders(): Map<String, Class<*>> {
    // Please override this
    return HashMap()
  }
}
