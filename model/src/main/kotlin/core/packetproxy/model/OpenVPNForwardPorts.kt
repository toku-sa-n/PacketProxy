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
import packetproxy.model.PropertyChangeEventType.FORWARD_PORTS
import packetproxy.util.errWithStackTrace

class OpenVPNForwardPorts(private val database: Database) : PropertyChangeListener {
  private val pcs = PropertyChangeSupport(this)

  private var dao: Dao<OpenVPNForwardPort, Int> =
    database.createTable(OpenVPNForwardPort::class.java, this)
  private var cache = DaoQueryCache<OpenVPNForwardPort>()

  init {
    if (!isLatestVersion()) {
      RecreateTable()
    }
    if (dao.countOf() == 0L) {
      create(OpenVPNForwardPort(OpenVPNForwardPort.TYPE.TCP, 80, 8080))
      create(OpenVPNForwardPort(OpenVPNForwardPort.TYPE.TCP, 443, 8443))
    }
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    pcs.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    pcs.removePropertyChangeListener(listener)
  }

  @Throws(Exception::class)
  fun create(forwardPort: OpenVPNForwardPort) {
    dao.createIfNotExists(forwardPort)
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
  fun delete(forwardPort: OpenVPNForwardPort) {
    dao.delete(forwardPort)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun update(forwardPort: OpenVPNForwardPort) {
    dao.update(forwardPort)
    cache.clear()
    firePropertyChange()
  }

  fun refresh() {
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun query(id: Int): OpenVPNForwardPort? {
    val ret = cache.query("query", id)
    if (ret != null) {
      return ret[0]
    }

    val forwardPort = dao.queryForId(id)

    cache.set("query", id, forwardPort)
    return forwardPort
  }

  @Throws(Exception::class)
  fun queryAll(): List<OpenVPNForwardPort> {
    var ret = cache.query("queryAll", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().query()

    cache.set("queryAll", 0, ret)
    return ret
  }

  fun firePropertyChange() {
    firePropertyChange(null)
  }

  fun firePropertyChange(arg: Any?) {
    pcs.firePropertyChange(FORWARD_PORTS.toString(), null, arg)
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
          dao = database.createTable(OpenVPNForwardPort::class.java, this)
          cache.clear()
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(OpenVPNForwardPort::class.java, this)
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
      dao
        .queryRaw("SELECT sql FROM sqlite_master WHERE name='openvpn_forward_ports'")
        .firstResult[0]
    return result ==
      "CREATE TABLE `openvpn_forward_ports` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `type` VARCHAR , `fromPort` INTEGER , `toPort` INTEGER , UNIQUE (`type`,`fromPort`,`toPort`) )"
  }

  @Throws(Exception::class)
  private fun RecreateTable() {
    val option =
      JOptionPane.showConfirmDialog(
        null,
        "OpenVPNForwardPortsテーブルの形式が更新されているため\n現在のテーブルを削除して再起動しても良いですか？",
        "テーブルの更新",
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE,
      )
    if (option == JOptionPane.YES_OPTION) {
      database.dropTable(OpenVPNForwardPort::class.java)
      dao = database.createTable(OpenVPNForwardPort::class.java, this)
    }
  }
}
