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
import java.util.stream.Collectors
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.model.PropertyChangeEventType.LISTEN_PORTS
import packetproxy.util.errWithStackTrace

open class ListenPorts(private val database: Database) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)

  private var dao: Dao<ListenPort, Int> = database.createTable(ListenPort::class.java, this)

  @Throws(Exception::class)
  fun create(listen: ListenPort) {
    if (isAlreadyEnabled(listen)) { // 他ポートが既にListenしていたら、Enableにさせない
      listen.setDisabled()
    }
    dao.createIfNotExists(listen)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(id: Int) {
    dao.deleteById(id)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(listen: ListenPort) {
    dao.delete(listen)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun update(listen: ListenPort) {
    if (listen.isEnabled() && isAlreadyEnabled(listen)) return
    dao.update(listen)
    firePropertyChange()
  }

  fun refresh() {
    firePropertyChange()
  }

  @Throws(Exception::class) fun query(id: Int): ListenPort? = dao.queryForId(id)

  @Throws(Exception::class)
  fun queryAll(): List<ListenPort> = dao.queryBuilder().orderBy("port", true).query()

  @Throws(Exception::class)
  fun queryEnabled(): List<ListenPort> = dao.queryBuilder().where().eq("enabled", true).query()

  @Throws(Exception::class)
  fun isAlreadyEnabled(port: ListenPort): Boolean =
    dao
      .queryBuilder()
      .where()
      .ne("id", port.getId())
      .and()
      .eq("port", port.getPort())
      .and()
      .eq("enabled", true)
      .query()
      .stream()
      .anyMatch { listenPort -> listenPort.getProtocol() == port.getProtocol() }

  @Throws(Exception::class)
  open fun queryEnabledByPort(protocol: ListenPort.Protocol, port: Int): ListenPort? {
    val rets =
      dao
        .queryBuilder()
        .where()
        .eq("port", port)
        .and()
        .eq("enabled", true)
        .query()
        .stream()
        .filter { listenPort -> listenPort.getProtocol() == protocol }
        .collect(Collectors.toList())
    return if (rets.size > 0) rets[0] else null
  }

  @Throws(Exception::class)
  fun queryByPortServer(protocol: ListenPort.Protocol, port: Int, server_id: Int): ListenPort? {
    val rets =
      dao
        .queryBuilder()
        .where()
        .eq("port", port)
        .and()
        .eq("server_id", server_id)
        .query()
        .stream()
        .filter { listenPort -> listenPort.getProtocol() == protocol }
        .collect(Collectors.toList())
    return if (rets.size > 0) rets[0] else null
  }

  @Throws(Exception::class)
  fun queryByHttpProxyPort(port: Int): ListenPort? {
    val rets =
      dao
        .queryBuilder()
        .where()
        .eq("type", ListenPort.TYPE.HTTP_PROXY)
        .and()
        .eq("port", port)
        .query()
    return if (rets.size > 0) rets[0] else null
  }

  @Throws(Exception::class)
  fun queryEnabledHttpProxis(): List<ListenPort> =
    dao
      .queryBuilder()
      .where()
      .eq("type", ListenPort.TYPE.HTTP_PROXY)
      .and()
      .eq("enabled", true)
      .query()

  @Throws(Exception::class)
  fun queryAllOfHttpProxis(): List<ListenPort> =
    dao.queryBuilder().where().eq("type", ListenPort.TYPE.HTTP_PROXY).query()

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  private fun firePropertyChange() {
    changes.firePropertyChange(LISTEN_PORTS.toString(), null, null)
  }

  private fun firePropertyChange(value: Any?) {
    changes.firePropertyChange(LISTEN_PORTS.toString(), null, value)
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
          dao = database.createTable(ListenPort::class.java, this)
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(ListenPort::class.java, this)
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
