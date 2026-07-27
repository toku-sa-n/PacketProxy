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

@DatabaseTable(tableName = "filters")
class Filter {
  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField(unique = true) private var name: String? = null

  @field:DatabaseField private var filter: String? = null

  constructor()

  constructor(name: String, filter: String) {
    this.name = name
    this.filter = filter
  }

  fun setName(name: String) {
    this.name = name
  }

  fun setFilter(filter: String) {
    this.filter = filter
  }

  fun getId(): Int = this.id

  fun getName(): String? = this.name

  fun getFilter(): String? = this.filter

  override fun toString(): String = String.format("[ %s: %s ]", this.name, this.filter)
}
