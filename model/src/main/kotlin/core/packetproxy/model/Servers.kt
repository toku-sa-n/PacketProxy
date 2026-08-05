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
import java.net.InetSocketAddress
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.model.PropertyChangeEventType.SERVERS
import packetproxy.util.errWithStackTrace

class Servers(private val database: Database) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)

  private var dao: Dao<Server, Int> = database.createTable(Server::class.java, this)
  private var cache = DaoQueryCache<Server>()

  init {
    SchemaMigrator.ensureColumns(dao)
  }

  @Throws(Exception::class)
  fun create(server: Server) {
    dao.createIfNotExists(server)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(server: Server) {
    dao.delete(server)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun queryByString(str: String): Server? {
    val all = this.queryAll()
    for (server in all) {
      if (server.toString() == str) {
        return server
      }
    }
    return null
  }

  @Throws(Exception::class)
  fun queryByHostNameAndPort(hostname: String, port: Int): Server? {
    val cache_key = hostname + port.toString()
    val ret = cache.query("queryByHostNameAndPort", cache_key)
    if (ret != null) {
      return ret[0]
    }

    val servers = dao.queryBuilder().where().eq("ip", hostname).and().eq("port", port).query()
    val server =
      if (servers.isEmpty()) {
        queryByHostName(hostname)
      } else {
        servers[0]
      }

    cache.set("queryByHostNameAndPort", cache_key, server!!)
    return server
  }

  @Throws(Exception::class)
  fun queryByAddress(addr: InetSocketAddress): Server? {
    val all = this.queryAll()
    if (addr.address == null) {
      throw Exception(String.format("cannot resolv hostname: %s", addr.hostName))
    }
    if (addr.getPort() == 0) {
      throw Exception("cannot resolv portnumber: 0")
    }
    val target = addr.address.hostAddress
    for (server in all) {
      val ips = server.getIps()
      for (ip in ips) {
        if (ip.hostAddress == target && server.getPort() == addr.getPort()) {
          return server
        }
      }
    }
    return null
  }

  @Throws(Exception::class)
  fun queryByHostName(hostname: String): Server? {
    val ret = cache.query("queryByHostName", hostname)
    if (ret != null) {
      return ret[0]
    }

    val server = dao.queryBuilder().where().eq("ip", hostname).queryForFirst()

    cache.set("queryByHostName", hostname, server)
    return server
  }

  @Throws(Exception::class)
  fun query(id: Int): Server? {
    val ret = cache.query("query", id)
    if (ret != null) {
      return ret[0]
    }

    val server = dao.queryForId(id)

    cache.set("query", id, server)
    return server
  }

  @Throws(Exception::class)
  fun queryAll(): List<Server> {
    var ret = cache.query("queryAll", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().orderBy("ip", true).query()

    cache.set("queryAll", 0, ret)
    return ret
  }

  @Throws(Exception::class)
  fun queryNonHttpProxies(): List<Server> {
    var ret = cache.query("queryNonHttpProxies", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().orderBy("ip", true).where().eq("http_proxy", false).query()

    cache.set("queryNonHttpProxies", 0, ret)
    return ret
  }

  @Throws(Exception::class)
  fun queryHttpProxies(): List<Server> {
    var ret = cache.query("queryHttpProxies", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().orderBy("ip", true).where().eq("http_proxy", true).query()

    cache.set("queryHttpProxies", 0, ret)
    return ret
  }

  @Throws(Exception::class)
  fun queryResolvedByDNS(): List<Server> {
    var ret = cache.query("queryResolvedByDNS", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().where().eq("resolved_by_dns", true).query()

    cache.set("queryResolvedByDNS", 0, ret)
    return ret
  }

  @Throws(Exception::class)
  fun queryResolvedByDNS6(): List<Server> {
    var ret = cache.query("queryResolvedByDNS6", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().where().eq("resolved_by_dns6", true).query()

    cache.set("queryResolvedByDNS6", 0, ret)
    return ret
  }

  @Throws(Exception::class)
  fun update(server: Server) {
    dao.update(server)
    cache.clear()
    firePropertyChange()
  }

  private fun firePropertyChange() {
    changes.firePropertyChange(SERVERS.toString(), null, null)
  }

  private fun firePropertyChange(arg: Any?) {
    changes.firePropertyChange(SERVERS.toString(), null, arg)
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
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
          dao = database.createTable(Server::class.java, this)
          cache.clear()
          SchemaMigrator.ensureColumns(dao)
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(Server::class.java, this)
          cache.clear()
          SchemaMigrator.ensureColumns(dao)
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
