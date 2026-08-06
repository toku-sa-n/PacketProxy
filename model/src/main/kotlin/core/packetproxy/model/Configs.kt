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
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import packetproxy.model.Database.DatabaseMessage
import packetproxy.util.errWithStackTrace

class Configs(private val database: Database) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)
  private var dao: Dao<Config, String> = database.createTable(Config::class.java, this)
  private var cache = DaoQueryCache<Config>()

  fun create(config: Config) {
    dao.createIfNotExists(config)
    cache.clear()
    firePropertyChange(PropertyChangeEventType.CONFIGS.toString(), null, null)
  }

  fun delete(config: Config) {
    dao.delete(config)
    cache.clear()
    firePropertyChange(PropertyChangeEventType.CONFIGS.toString(), null, null)
  }

  fun query(key: String): Config? {
    val cached = cache.query("query", key)
    if (cached != null) {
      return cached[0]
    }
    val config = dao.queryForId(key)
    cache.set("query", key, config)
    return config
  }

  fun queryAll(): List<Config> {
    val cached = cache.query("queryAll", 0)
    if (cached != null) {
      return cached
    }
    val configs = dao.queryForAll()
    cache.set("queryAll", 0, configs)
    return configs
  }

  fun update(config: Config) {
    dao.update(config)
    cache.clear()
    firePropertyChange(PropertyChangeEventType.CONFIGS.toString(), null, null)
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  fun firePropertyChange(propertyName: String, oldValue: Any?, newValue: Any?) {
    changes.firePropertyChange(propertyName, oldValue, newValue)
  }

  override fun propertyChange(event: PropertyChangeEvent) {
    if (!PropertyChangeEventType.DATABASE_MESSAGE.matches(event)) {
      return
    }
    try {
      when (event.newValue as DatabaseMessage) {
        DatabaseMessage.PAUSE,
        DatabaseMessage.RESUME -> {}
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          dao = database.createTable(Config::class.java, this)
          cache.clear()
          firePropertyChange(PropertyChangeEventType.CONFIGS.toString(), null, event.newValue)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(Config::class.java, this)
          cache.clear()
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
