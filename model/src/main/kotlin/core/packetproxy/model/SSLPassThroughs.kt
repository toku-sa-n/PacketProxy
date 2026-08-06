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
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.model.PropertyChangeEventType.SSL_PASS_THROUGHS
import packetproxy.util.errWithStackTrace

class SSLPassThroughs(private val database: Database) : PropertyChangeListener {
  var listenPortRebooter: ListenPortRebooter? = null
  private val changes = PropertyChangeSupport(this)

  private var dao: Dao<SSLPassThrough, Int> = database.createTable(SSLPassThrough::class.java, this)
  private var cache = DaoQueryCache<SSLPassThrough>()

  init {
    SchemaMigrator.ensureCompatible(database, dao, "sslpassthroughs") {
      database.dropTable(SSLPassThrough::class.java)
      dao = database.createTable(SSLPassThrough::class.java, this)
    }
    if (dao.countOf() == 0L) {
      create(SSLPassThrough(".*\\.apple\\.com", SSLPassThrough.ALL_PORTS))
      create(SSLPassThrough(".*\\.googleapis\\.com", SSLPassThrough.ALL_PORTS))
    }
  }

  @Throws(Exception::class)
  fun create(sslPassThrough: SSLPassThrough) {
    dao.createIfNotExists(sslPassThrough)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(id: Int) {
    dao.deleteById(id)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(sslPassThrough: SSLPassThrough) {
    dao.delete(sslPassThrough)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun update(sslPassThrough: SSLPassThrough) {
    dao.update(sslPassThrough)
    cache.clear()
    firePropertyChange()
  }

  fun refresh() {
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun query(id: Int): SSLPassThrough? {
    val ret = cache.query("query", id)
    if (ret != null) {
      return ret[0]
    }

    val ssl_pass_through = dao.queryForId(id)

    cache.set("query", id, ssl_pass_through)
    return ssl_pass_through
  }

  @Throws(Exception::class)
  fun queryAll(): List<SSLPassThrough> {
    var ret = cache.query("queryAll", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().query()

    cache.set("queryAll", 0, ret)
    return ret
  }

  @Throws(Exception::class)
  fun queryEnabled(serverName: String): List<SSLPassThrough> {
    var ret = cache.query("queryEnabled", serverName)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().where().eq("server_name", serverName).and().eq("enabled", true).query()

    cache.set("queryEnabled", serverName, ret)
    return ret
  }

  @Throws(Exception::class)
  fun includes(serverName: String, listenPort: Int): Boolean {
    val cache_key = "$serverName|$listenPort"
    var spts = cache.query("includes", cache_key)
    if (spts == null) {
      spts =
        dao
          .queryBuilder()
          .where()
          .eq("listen_port", listenPort)
          .or()
          .eq("listen_port", SSLPassThrough.ALL_PORTS)
          .and()
          .eq("enabled", true)
          .query()
      cache.set("includes", cache_key, spts)
    }
    for (spt in spts) {
      if (serverName.matches(spt.getServerName()!!.toRegex())) {
        return true
      }
    }
    return false
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  private fun firePropertyChange() {
    firePropertyChange(null)
  }

  private fun firePropertyChange(value: Any?) {
    try {
      // 設定を反映するためにポートを再起動する
      listenPortRebooter?.rebootIfHTTPProxyRunning()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    changes.firePropertyChange(SSL_PASS_THROUGHS.toString(), null, value)
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (!DATABASE_MESSAGE.matches(evt)) {
      return
    }

    val message = evt.newValue as DatabaseMessage
    try {
      when (message) {
        DatabaseMessage.PAUSE,
        DatabaseMessage.RESUME,
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          dao = database.createTable(SSLPassThrough::class.java, this)
          cache.clear()
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(SSLPassThrough::class.java, this)
          cache.clear()
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
