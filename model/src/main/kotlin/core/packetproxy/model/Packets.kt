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
import java.util.concurrent.Executors
import javax.swing.JOptionPane
import packetproxy.common.Logger
import packetproxy.model.Database.DatabaseMessage
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class Packets(private val database: Database, restore: Boolean) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)
  private var dao: Dao<Packet, Int> = database.createTable(Packet::class.java)
  private val executor = Executors.newSingleThreadExecutor()

  init {
    database.addPropertyChangeListener(this)
    if (restore) {
      if (!isLatestVersion()) {
        recreateTable()
      }
      log("load history...")
      log("load %d records.", dao.countOf())
    }
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  fun create(packet: Packet) {
    synchronized(dao) { dao.createIfNotExists(packet) }
    firePropertyChange()
  }

  fun refresh() {
    firePropertyChange()
  }

  fun updateSync(packet: Packet) {
    if (database.isAlertFileSize()) {
      firePropertyChange(true)
    }
    val status = synchronized(dao) { dao.createOrUpdate(packet) }
    firePropertyChange(if (status.isCreated) packet.getId() * -1 else packet.getId())
  }

  fun update(packet: Packet) {
    executor.execute {
      try {
        updateSync(packet)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  fun deleteAll() {
    synchronized(dao) { dao.deleteBuilder().delete() }
    firePropertyChange()
  }

  fun delete(packet: Packet) {
    synchronized(dao) { dao.delete(packet) }
    firePropertyChange()
  }

  fun countOf(): Long = dao.countOf()

  fun query(id: Int): Packet? = dao.queryForId(id)

  fun queryAllIdsAndColors(): List<Packet> =
    dao
      .queryBuilder()
      .selectColumns("id", "color", "direction", "group", "encoder_name")
      .orderBy("id", true)
      .query()

  fun queryRange(offset: Long, limit: Long): List<Packet> =
    dao.queryBuilder().offset(offset).limit(limit).orderBy("id", true).query()

  fun queryAll(): List<Packet> = dao.queryBuilder().orderBy("id", true).query()

  fun queryMoreThan(date: Int): List<Packet> = dao.queryBuilder().where().gt("id", date).query()

  fun queryFullText(search: String, start: Int): List<Packet> =
    dao
      .queryBuilder()
      .selectColumns("group")
      .where()
      .ge("id", start)
      .and()
      .like("decoded_data", "%%%s%%".format(search))
      .query()

  fun queryFullTextById(search: String, id: Int): List<Packet> =
    dao
      .queryBuilder()
      .selectColumns("group")
      .where()
      .eq("id", id)
      .and()
      .like("decoded_data", "%%%s%%".format(search))
      .query()

  fun queryFullText(search: String): List<Packet> =
    dao
      .queryRaw(
        "SELECT `group`,`id` FROM `packets` WHERE `decoded_data` GLOB '*%s*';".format(search),
        dao.rawRowMapper,
      )
      .results

  fun queryFullText_i(search: String): List<Packet> =
    dao
      .queryBuilder()
      .selectColumns("group")
      .where()
      .like("decoded_data", "%%%s%%".format(search))
      .query()

  fun firePropertyChange() {
    changes.firePropertyChange(PropertyChangeEventType.PACKETS.toString(), null, null)
  }

  fun firePropertyChange(arg: Any?) {
    changes.firePropertyChange(PropertyChangeEventType.PACKETS.toString(), null, arg)
  }

  fun outputAllPackets(filename: String): String = Logger(queryAll()).outputToFile(filename)

  fun isEmpty(): Boolean = dao.queryBuilder().limit(1L).query().isEmpty()

  fun handleDatabaseMessage(message: DatabaseMessage) {
    try {
      when (message) {
        DatabaseMessage.PAUSE,
        DatabaseMessage.RESUME,
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          dao = database.createTable(Packet::class.java)
          val result =
            dao.queryRaw("SELECT sql FROM sqlite_master WHERE name='packets'").firstResult[0]
          if (!result.contains("`color` VARCHAR"))
            dao.executeRaw("ALTER TABLE `packets` ADD COLUMN color VARCHAR")
          if (!result.contains("`job_id` VARCHAR"))
            dao.executeRaw("ALTER TABLE `packets` ADD COLUMN job_id VARCHAR")
          if (!result.contains("`temporary_id` VARCHAR"))
            dao.executeRaw("ALTER TABLE `packets` ADD COLUMN temporary_id VARCHAR")
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(Packet::class.java)
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun propertyChange(event: PropertyChangeEvent) {
    if (!PropertyChangeEventType.DATABASE_MESSAGE.matches(event)) {
      return
    }
    handleDatabaseMessage(event.newValue as DatabaseMessage)
  }

  private fun isLatestVersion(): Boolean =
    dao.queryRaw("SELECT sql FROM sqlite_master WHERE name='packets'").firstResult[0] ==
      "CREATE TABLE `packets` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `direction` VARCHAR , `decoded_data` BLOB , `modified_data` BLOB , `sent_data` BLOB , `received_data` BLOB , `listen_port` INTEGER , `client_ip` VARCHAR , `client_port` INTEGER , `server_ip` VARCHAR , `server_name` VARCHAR , `server_port` INTEGER , `use_ssl` BOOLEAN , `content_type` VARCHAR , `encoder_name` VARCHAR , `alpn` VARCHAR , `modified` BOOLEAN , `resend` BOOLEAN , `date` BIGINT , `conn` INTEGER , `group` BIGINT , `color` VARCHAR , `job_id` VARCHAR , `temporary_id` VARCHAR )"

  private fun recreateTable() {
    val option =
      JOptionPane.showConfirmDialog(
        null,
        "packetsテーブルの形式が更新されているため\n現在のテーブルを削除して再起動しても良いですか？",
        "テーブルの更新",
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE,
      )
    if (option != JOptionPane.YES_OPTION) {
      return
    }
    database.dropTable(Packet::class.java)
    dao = database.createTable(Packet::class.java)
  }
}
