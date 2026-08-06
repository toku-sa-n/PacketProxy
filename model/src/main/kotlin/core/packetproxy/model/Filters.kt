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

import com.j256.ormlite.dao.Dao
import packetproxy.model.PropertyChangeEventType.FILTERS

class Filters(database: Database) : AbstractDaoManager(database) {
  override val updateEventType = FILTERS

  private var dao: Dao<Filter, Int> = database.createTable(Filter::class.java, this)

  init {
    SchemaMigrator.ensureCompatible(database, dao, "filters") {
      database.dropTable(Filter::class.java)
      dao = database.createTable(Filter::class.java, this)
    }
  }

  @Throws(Exception::class)
  fun create(filter: Filter) {
    dao.createIfNotExists(filter)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(filter: Filter) {
    dao.delete(filter)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun deleteByName(name: String) {
    dao.delete(queryByName(name))
    firePropertyChange()
  }

  @Throws(Exception::class) fun query(id: Int): Filter? = dao.queryForId(id)

  @Throws(Exception::class)
  fun queryByName(name: String): List<Filter> = dao.queryBuilder().where().eq("name", name).query()

  @Throws(Exception::class)
  fun queryAll(): List<Filter> = dao.queryBuilder().orderBy("id", false).query()

  @Throws(Exception::class)
  fun update(filter: Filter) {
    dao.update(filter)
    firePropertyChange()
  }

  override fun onReconnect() {
    dao = database.createTable(Filter::class.java, this)
  }

  override fun onRecreate() {
    dao = database.createTable(Filter::class.java, this)
  }
}
