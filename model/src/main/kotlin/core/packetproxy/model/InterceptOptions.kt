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
import packetproxy.model.InterceptOption.Direction
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.model.PropertyChangeEventType.INTERCEPT_OPTIONS
import packetproxy.util.errWithStackTrace

class InterceptOptions(private val database: Database) : PropertyChangeListener {
  private val pcs = PropertyChangeSupport(this)

  private var dao: Dao<InterceptOption, Int> =
    database.createTable(InterceptOption::class.java, this)
  private var enabled = ConfigBoolean(Configs(database), "InterceptOptions")
  private var cache = DaoQueryCache<InterceptOption>()

  init {
    SchemaMigrator.ensureCompatible(database, dao, "interceptOptions") {
      database.dropTable(InterceptOption::class.java)
      dao = database.createTable(InterceptOption::class.java, this)
    }
  }

  @Throws(Exception::class)
  private fun setDefaultRulesIfNotFound() {
    val i1Num =
      dao
        .queryBuilder()
        .where()
        .eq("Direction", InterceptOption.Direction.ALL_THE_OTHER_REQUESTS)
        .query()
        .size
    if (i1Num == 0) {
      val i1 =
        InterceptOption(
          InterceptOption.Direction.ALL_THE_OTHER_REQUESTS,
          InterceptOption.Type.REQUEST,
          InterceptOption.Relationship.ARE_INTERCEPTED,
          "",
          InterceptOption.Method.UNDEFINED,
          null,
        )
      i1.setEnabled()
      dao.create(i1)
      cache.clear()
    }
    val i2Num =
      dao
        .queryBuilder()
        .where()
        .eq("Direction", InterceptOption.Direction.ALL_THE_OTHER_RESPONSES)
        .query()
        .size
    if (i2Num == 0) {
      val i2 =
        InterceptOption(
          InterceptOption.Direction.ALL_THE_OTHER_RESPONSES,
          InterceptOption.Type.REQUEST,
          InterceptOption.Relationship.ARE_INTERCEPTED,
          "",
          InterceptOption.Method.UNDEFINED,
          null,
        )
      i2.setEnabled()
      dao.create(i2)
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
  fun create(intercept_option: InterceptOption) {
    intercept_option.setEnabled()
    dao.createIfNotExists(intercept_option)
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
  fun delete(intercept_option: InterceptOption) {
    dao.delete(intercept_option)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun update(intercept_option: InterceptOption) {
    dao.update(intercept_option)
    cache.clear()
    firePropertyChange()
  }

  fun refresh() {
    firePropertyChange()
  }

  @Throws(Exception::class) fun query(id: Int): InterceptOption? = dao.queryForId(id)

  private fun sort(list: List<InterceptOption>): List<InterceptOption> {
    val sorted = ArrayList<InterceptOption>()
    for (l in list) {
      if (l.isDirection(Direction.REQUEST)) {
        sorted.add(l)
      }
    }
    for (l in list) {
      if (l.isDirection(Direction.ALL_THE_OTHER_REQUESTS)) {
        sorted.add(l)
      }
    }
    for (l in list) {
      if (l.isDirection(Direction.RESPONSE)) {
        sorted.add(l)
      }
    }
    for (l in list) {
      if (l.isDirection(Direction.ALL_THE_OTHER_RESPONSES)) {
        sorted.add(l)
      }
    }
    return sorted
  }

  @Throws(Exception::class)
  fun queryAll(): List<InterceptOption> {
    try {
      val retCached = cache.query("queryAll", 0)
      if (retCached != null) {
        return retCached
      }

      setDefaultRulesIfNotFound()
      val list = dao.queryBuilder().query()
      val ret = sort(list)

      cache.set("queryAll", 0, ret)
      return ret
    } catch (e: Exception) {
      database.dropTable(InterceptOption::class.java)
      dao = database.createTable(InterceptOption::class.java, this)
      setDefaultRulesIfNotFound()
      return dao.queryBuilder().query()
    }
  }

  @Throws(Exception::class)
  fun queryEnabled(server: Server?): List<InterceptOption> {
    var server_id = InterceptOption.ALL_SERVER
    if (server != null) {
      server_id = server.getId()
    }

    val retCached = cache.query("queryEnabled", server_id)
    if (retCached != null) {
      return retCached
    }

    setDefaultRulesIfNotFound()
    val list =
      dao
        .queryBuilder()
        .where()
        .eq("server_id", server_id)
        .or()
        .eq("server_id", InterceptOption.ALL_SERVER)
        .and()
        .eq("enabled", true)
        .query()
    val ret = sort(list)

    cache.set("queryEnabled", server_id, ret)
    return ret
  }

  @Throws(Exception::class)
  fun interceptOnRequest(server: Server?, client_packet: Packet): Boolean {
    for (intercept in queryEnabled(server)) {
      if (intercept.isDirection(InterceptOption.Direction.REQUEST)) {
        when (intercept.getRelationship()) {
          InterceptOption.Relationship.IS_INTERCEPTED_IF_IT_MATCHES -> {
            if (intercept.match(client_packet, null)) {
              return true
            }
          }
          InterceptOption.Relationship.IS_NOT_INTERCEPTED_IF_IT_MATCHES -> {
            if (intercept.match(client_packet, null)) {
              return false
            }
          }
          else -> {}
        }
      } else if (intercept.isDirection(Direction.ALL_THE_OTHER_REQUESTS)) {
        when (intercept.getRelationship()) {
          InterceptOption.Relationship.ARE_INTERCEPTED -> return true
          InterceptOption.Relationship.ARE_NOT_INTERCEPTED -> return false
          else -> return true
        }
      }
    }
    return true
  }

  @Throws(Exception::class)
  fun interceptOnResponse(server: Server?, client_packet: Packet, server_packet: Packet): Boolean {
    for (intercept in queryEnabled(server)) {
      if (intercept.getDirection() == InterceptOption.Direction.RESPONSE) {
        when (intercept.getRelationship()) {
          InterceptOption.Relationship.IS_INTERCEPTED_IF_IT_MATCHES -> {
            if (intercept.match(client_packet, server_packet)) {
              return true
            }
          }
          InterceptOption.Relationship.IS_NOT_INTERCEPTED_IF_IT_MATCHES -> {
            if (intercept.match(client_packet, server_packet)) {
              return false
            }
          }
          InterceptOption.Relationship.IS_INTERCEPTED_IF_REQUEST_WAS_INTERCEPTED -> {
            // パケットにフラグを立てた方がいいけどDBが変わるので一旦これで
            if (interceptOnRequest(server, client_packet)) {
              return true
            }
          }
          else -> {}
        }
      } else if (intercept.isDirection(Direction.ALL_THE_OTHER_RESPONSES)) {
        when (intercept.getRelationship()) {
          InterceptOption.Relationship.ARE_INTERCEPTED -> return true
          InterceptOption.Relationship.ARE_NOT_INTERCEPTED -> return false
          else -> {}
        }
      }
    }
    return true
  }

  fun firePropertyChange() {
    firePropertyChange(null)
  }

  fun firePropertyChange(arg: Any?) {
    pcs.firePropertyChange(INTERCEPT_OPTIONS.toString(), null, arg)
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
          dao = database.createTable(InterceptOption::class.java, this)
          cache.clear()
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(InterceptOption::class.java, this)
          cache.clear()
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  fun setEnabled(enabled: Boolean) {
    this.enabled.setState(enabled)
  }

  @Throws(Exception::class) fun isEnabled(): Boolean = this.enabled.getState()
}
