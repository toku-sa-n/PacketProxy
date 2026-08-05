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
import packetproxy.model.PropertyChangeEventType.MODIFICATIONS_UPDATED
import packetproxy.util.errWithStackTrace

class Modifications(private val database: Database) : PropertyChangeListener {
  private val pcs = PropertyChangeSupport(this)

  private var dao: Dao<Modification, Int> = database.createTable(Modification::class.java, this)
  private var cache = DaoQueryCache<Modification>()

  init {
    SchemaMigrator.ensureCompatible(database, dao, "modifications") {
      database.dropTable(Modification::class.java)
      dao = database.createTable(Modification::class.java, this)
      cache.clear()
    }
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    pcs.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    pcs.removePropertyChangeListener(listener)
  }

  @Throws(Exception::class)
  fun create(modification: Modification) {
    dao.createIfNotExists(modification)
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
  fun delete(modification: Modification) {
    dao.delete(modification)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun update(modification: Modification) {
    dao.update(modification)
    cache.clear()
    firePropertyChange()
  }

  fun refresh() {
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun query(id: Int): Modification? {
    val ret = cache.query("query", 0)
    if (ret != null) {
      return ret[0]
    }

    val modification = dao.queryForId(id)

    cache.set("query", id, modification)
    return modification
  }

  @Throws(Exception::class)
  fun queryAll(): List<Modification> {
    var ret = cache.query("queryAll", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().query()

    cache.set("queryAll", 0, ret)
    return ret
  }

  @Throws(Exception::class)
  fun queryEnabled(server: Server?): List<Modification> {
    var server_id = Modification.ALL_SERVER
    if (server != null) {
      server_id = server.getId()
    }

    var ret = cache.query("queryEnabled", server_id)
    if (ret != null) {
      return ret
    }

    ret =
      dao
        .queryBuilder()
        .where()
        .eq("server_id", server_id)
        .or()
        .eq("server_id", Modification.ALL_SERVER)
        .and()
        .eq("enabled", true)
        .query()

    cache.set("queryEnabled", server_id, ret)
    return ret
  }

  @Throws(Exception::class)
  fun replaceOnRequest(
    data: ByteArray,
    server: Server?,
    client_packet: Packet,
    requestPath: String?,
  ): ByteArray {
    var data = data
    for (mod in queryEnabled(server)) {
      if (!mod.matchesPath(requestPath)) {
        continue
      }
      if (
        mod.getDirection() == Modification.Direction.CLIENT_REQUEST ||
          mod.getDirection() == Modification.Direction.ALL
      )
        data = mod.replace(data, client_packet)
    }
    return data
  }

  @Throws(Exception::class)
  fun replaceOnResponse(
    data: ByteArray,
    server: Server?,
    server_packet: Packet,
    requestPath: String?,
  ): ByteArray {
    var data = data
    for (mod in queryEnabled(server)) {
      if (!mod.matchesPath(requestPath)) {
        continue
      }
      if (
        mod.getDirection() == Modification.Direction.SERVER_RESPONSE ||
          mod.getDirection() == Modification.Direction.ALL
      )
        data = mod.replace(data, server_packet)
    }
    return data
  }

  private fun firePropertyChange() {
    pcs.firePropertyChange(MODIFICATIONS_UPDATED.toString(), null, null)
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (evt.source !is Database) {
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
          dao = database.createTable(Modification::class.java, this)
          cache.clear()
          firePropertyChange()
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(Modification::class.java, this)
          cache.clear()
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
