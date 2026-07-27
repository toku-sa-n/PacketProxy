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
import javax.swing.JOptionPane
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.model.PropertyChangeEventType.SSL_PASS_THROUGHS
import packetproxy.util.Logging.errWithStackTrace

class SSLPassThroughs private constructor() : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)

  private var database: Database = Database.getInstance()
  private var dao: Dao<SSLPassThrough, Int> = database.createTable(SSLPassThrough::class.java, this)
  private var cache = DaoQueryCache<SSLPassThrough>()
  private var listenPorts: ListenPorts = ListenPorts.getInstance()

  init {
    if (!isLatestVersion()) {
      RecreateTable()
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
  fun queryEnabled(serverName: String, listenPort: ListenPort): List<SSLPassThrough> {
    val cache_key = serverName + listenPort.hashCode().toString()
    var ret = cache.query("queryEnabled2", cache_key)
    if (ret != null) {
      return ret
    }

    ret =
      dao
        .queryBuilder()
        .where()
        .eq("server_name", serverName)
        .or()
        .eq("listen_port", listenPort)
        .and()
        .eq("enabled", true)
        .query()

    cache.set("queryEnabled2", cache_key, ret)
    return ret
  }

  @Throws(Exception::class)
  fun includes(serverName: String, listenPort: Int): Boolean {
    val cache_key = serverName + listenPort.toString()
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
    listenPorts.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
    listenPorts.removePropertyChangeListener(listener)
  }

  private fun firePropertyChange() {
    firePropertyChange(null)
  }

  private fun firePropertyChange(value: Any?) {
    try {
      // 設定を反映するためにポートを再起動する
      ListenPortRebootHooks.rebootIfHTTPProxyRunning()
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
        DatabaseMessage.PAUSE -> {
          // TODO ロックを取る
        }
        DatabaseMessage.RESUME -> {
          // TODO ロックを解除
        }
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          database = Database.getInstance()
          dao = database.createTable(SSLPassThrough::class.java, this)
          cache.clear()
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          database = Database.getInstance()
          dao = database.createTable(SSLPassThrough::class.java, this)
          cache.clear()
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  private fun isLatestVersion(): Boolean {
    val result =
      dao.queryRaw("SELECT sql FROM sqlite_master WHERE name='sslpassthroughs'").firstResult[0]
    return result ==
      "CREATE TABLE `sslpassthroughs` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `enabled` BOOLEAN , `server_name` VARCHAR , `listen_port` INTEGER , UNIQUE (`server_name`,`listen_port`) )"
  }

  @Throws(Exception::class)
  private fun RecreateTable() {
    val option =
      JOptionPane.showConfirmDialog(
        null,
        "SSLPassThroughsテーブルの形式が更新されているため\n現在のテーブルを削除して再起動しても良いですか？",
        "テーブルの更新",
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE,
      )
    if (option == JOptionPane.YES_OPTION) {
      database.dropTable(SSLPassThrough::class.java)
      dao = database.createTable(SSLPassThrough::class.java, this)
    }
  }

  companion object {
    private var instance: SSLPassThroughs? = null

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): SSLPassThroughs {
      if (instance == null) {
        instance = SSLPassThroughs()
      }
      return instance!!
    }
  }
}
