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
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.JOptionPane
import packetproxy.common.Logger
import packetproxy.model.Database.DatabaseMessage
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class Packets(private val database: Database, restore: Boolean) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)
  private var dao: Dao<Packet, Int> = database.createTable(Packet::class.java)
  private val executor = Executors.newSingleThreadExecutor()
  private val pendingUpdates = LinkedHashMap<String, Packet>()
  private val updateScheduled = AtomicBoolean(false)

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

  // packet.getId() > 0 のときはdao.update()を使う。dao.update()はレコード全体を書き込むため、
  // 一部カラムのみをselectしたpartial-select済みのPacket（BLOB列を持たない）を渡すと、
  // 未選択カラムがデフォルト値で上書きされデータを消してしまう。updateSync()には常に
  // 全カラムを保持したPacketのみを渡すこと。
  fun updateSync(packet: Packet) {
    if (database.isAlertFileSize()) {
      firePropertyChange(true)
    }
    val id = packet.getId()
    if (id > 0) {
      synchronized(dao) { dao.update(packet) }
      firePropertyChange(id)
      return
    }
    val status = synchronized(dao) { dao.createOrUpdate(packet) }
    firePropertyChange(if (status.isCreated) packet.getId() * -1 else packet.getId())
  }

  fun update(packet: Packet) {
    synchronized(pendingUpdates) { pendingUpdates[packetUpdateKey(packet)] = packet }
    schedulePendingUpdates()
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

  fun queryPage(offset: Long, limit: Long, ascending: Boolean): List<Packet> =
    dao.queryBuilder().offset(offset).limit(limit).orderBy("id", ascending).query()

  // BLOB列(decoded_data等)を含まないメタデータのみを返す。一覧のスケルトン表示など、
  // 本文データを必要としない箇所で queryPage/queryRange の代わりに使うことで、
  // 大きなBLOBの読み出しコストを避けられる。
  fun queryPageMetadata(offset: Long, limit: Long, ascending: Boolean): List<Packet> =
    dao
      .queryBuilder()
      .selectColumns(
        "id",
        "direction",
        "listen_port",
        "client_ip",
        "client_port",
        "server_ip",
        "server_name",
        "server_port",
        "use_ssl",
        "content_type",
        "encoder_name",
        "alpn",
        "modified",
        "resend",
        "date",
        "conn",
        "group",
        "color",
        "job_id",
        "temporary_id",
      )
      .offset(offset)
      .limit(limit)
      .orderBy("id", ascending)
      .query()

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

  fun queryPairedPacket(
    group: Long,
    conn: Int,
    direction: Packet.Direction,
    excludeId: Int,
  ): Packet? =
    dao
      .queryBuilder()
      .where()
      .eq("group", group)
      .and()
      .eq("conn", conn)
      .and()
      .eq("direction", direction)
      .and()
      .ne("id", excludeId)
      .queryForFirst()

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

  private fun flushPendingUpdates() {
    while (true) {
      val batch =
        synchronized(pendingUpdates) {
          if (pendingUpdates.isEmpty()) {
            return
          }
          val copied = pendingUpdates.values.toList()
          pendingUpdates.clear()
          copied
        }
      for (packet in batch) {
        updateSync(packet)
      }
    }
  }

  private fun packetUpdateKey(packet: Packet): String {
    val id = packet.getId()
    if (id > 0) {
      return "id:$id"
    }
    return "obj:${System.identityHashCode(packet)}"
  }

  private fun schedulePendingUpdates() {
    if (!updateScheduled.compareAndSet(false, true)) {
      return
    }
    executor.execute {
      try {
        flushPendingUpdates()
      } catch (e: Exception) {
        errWithStackTrace(e)
      } finally {
        updateScheduled.set(false)
        if (synchronized(pendingUpdates) { pendingUpdates.isNotEmpty() }) {
          schedulePendingUpdates()
        }
      }
    }
  }
}
