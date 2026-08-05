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
    SchemaMigrator.ensureColumns(dao)
    ensurePairIndex()
    ensureFts()
    if (restore) {
      SchemaMigrator.ensureCompatible(database, dao, "packets") {
        database.dropTable(Packet::class.java)
        dao = database.createTable(Packet::class.java)
        ensurePairIndex()
        ensureFts()
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
    synchronized(dao) {
      dao.createIfNotExists(packet)
      syncFts(packet)
    }
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
      synchronized(dao) {
        dao.update(packet)
        syncFts(packet)
      }
      firePropertyChange(id)
      return
    }
    val status =
      synchronized(dao) {
        val result = dao.createOrUpdate(packet)
        syncFts(packet)
        result
      }
    firePropertyChange(if (status.isCreated) packet.getId() * -1 else packet.getId())
  }

  fun update(packet: Packet) {
    synchronized(pendingUpdates) { pendingUpdates[packetUpdateKey(packet)] = packet }
    schedulePendingUpdates()
  }

  /** Update content_type without rewriting BLOB columns. No-op when id <= 0. */
  fun updateContentType(id: Int, contentType: String?) {
    if (id <= 0) {
      return
    }
    synchronized(dao) {
      dao
        .updateBuilder()
        .apply {
          updateColumnValue("content_type", contentType)
          where().eq("id", id)
        }
        .update()
    }
    firePropertyChange(id)
  }

  /** Update color without rewriting BLOB columns. No-op when id <= 0. */
  fun updateColor(id: Int, color: String?) {
    if (id <= 0) {
      return
    }
    synchronized(dao) {
      dao
        .updateBuilder()
        .apply {
          updateColumnValue("color", color)
          where().eq("id", id)
        }
        .update()
    }
    firePropertyChange(id)
  }

  /** Update modified flag without rewriting BLOB columns. No-op when id <= 0. */
  fun updateModified(id: Int, modified: Boolean) {
    if (id <= 0) {
      return
    }
    synchronized(dao) {
      dao
        .updateBuilder()
        .apply {
          updateColumnValue("modified", modified)
          where().eq("id", id)
        }
        .update()
    }
    firePropertyChange(id)
  }

  fun deleteAll() {
    synchronized(dao) {
      dao.deleteBuilder().delete()
      dao.executeRaw("DELETE FROM packets_fts")
    }
    firePropertyChange()
  }

  fun delete(packet: Packet) {
    synchronized(dao) {
      dao.delete(packet)
      deleteFts(packet.getId())
    }
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
        "summarized_request",
        "summarized_response",
        "display_length",
      )
      .offset(offset)
      .limit(limit)
      .orderBy("id", ascending)
      .query()

  fun queryByIdMetadata(id: Int): Packet? =
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
        "summarized_request",
        "summarized_response",
        "display_length",
      )
      .where()
      .eq("id", id)
      .queryForFirst()

  fun queryAllMetadata(): List<Packet> =
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
        "summarized_request",
        "summarized_response",
        "display_length",
      )
      .orderBy("id", true)
      .query()

  fun queryAll(): List<Packet> = dao.queryBuilder().orderBy("id", true).query()

  fun queryMoreThan(date: Int): List<Packet> = dao.queryBuilder().where().gt("id", date).query()

  fun queryFullText(search: String, start: Int): List<Packet> =
    queryFts(search).filter { it.getId() >= start }

  fun queryFullTextById(search: String, id: Int): List<Packet> =
    queryFts(search).filter { it.getId() == id }

  fun queryFullText(search: String): List<Packet> = queryFts(search)

  fun queryFullText_i(search: String): List<Packet> = queryFts(search)

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
          if (!result.contains("`summarized_request`"))
            dao.executeRaw("ALTER TABLE `packets` ADD COLUMN summarized_request VARCHAR")
          if (!result.contains("`summarized_response`"))
            dao.executeRaw("ALTER TABLE `packets` ADD COLUMN summarized_response VARCHAR")
          if (!result.contains("`display_length`"))
            dao.executeRaw("ALTER TABLE `packets` ADD COLUMN display_length INTEGER DEFAULT 0")
          ensurePairIndex()
          ensureFts()
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

  private fun ensurePairIndex() {
    dao.executeRaw(
      "CREATE INDEX IF NOT EXISTS packets_pair_idx ON packets(`group`, `conn`, `direction`)"
    )
  }

  private fun ensureFts() {
    dao.executeRaw(
      """
      CREATE VIRTUAL TABLE IF NOT EXISTS packets_fts USING fts5(
        packet_id UNINDEXED,
        group_id UNINDEXED,
        body,
        tokenize = 'unicode61'
      )
      """
        .trimIndent()
    )
  }

  private fun syncFts(packet: Packet) {
    val id = packet.getId()
    if (id <= 0) {
      return
    }
    deleteFts(id)
    val bodyBytes =
      when {
        packet.getDecodedData().isNotEmpty() -> packet.getDecodedData()
        packet.getModifiedData().isNotEmpty() -> packet.getModifiedData()
        else -> packet.getReceivedData()
      }
    val body =
      try {
        String(bodyBytes, Charsets.UTF_8)
      } catch (_: Exception) {
        String(bodyBytes, Charsets.ISO_8859_1)
      }
    val escaped = body.replace("'", "''")
    dao.executeRaw(
      "INSERT INTO packets_fts(packet_id, group_id, body) VALUES (%d, %d, '%s')"
        .format(id, packet.getGroup(), escaped.take(200_000))
    )
  }

  private fun deleteFts(id: Int) {
    if (id <= 0) {
      return
    }
    dao.executeRaw("DELETE FROM packets_fts WHERE packet_id = %d".format(id))
  }

  private fun queryFts(search: String): List<Packet> {
    if (search.isEmpty()) {
      return emptyList()
    }
    // FTS5 MATCH is case-insensitive with unicode61; quote the phrase for literal match.
    val escaped = search.replace("\"", "\"\"").replace("'", "''")
    val match = "\"$escaped\""
    val rows =
      dao.queryRaw(
        "SELECT group_id, packet_id FROM packets_fts WHERE packets_fts MATCH '%s'".format(match)
      )
    val results = ArrayList<Packet>()
    for (row in rows.results) {
      try {
        val packetId = row[1].toInt()
        val packet = queryByIdMetadata(packetId) ?: continue
        results.add(packet)
      } catch (_: Exception) {
        // skip bad rows
      }
    }
    return results
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
      if (database.isAlertFileSize()) {
        firePropertyChange(true)
      }
      val notifiedIds = ArrayList<Int>(batch.size)
      synchronized(dao) {
        dao.callBatchTasks {
          for (packet in batch) {
            val id = packet.getId()
            if (id > 0) {
              dao.update(packet)
              syncFts(packet)
              notifiedIds.add(id)
              continue
            }
            val status = dao.createOrUpdate(packet)
            syncFts(packet)
            notifiedIds.add(if (status.isCreated) packet.getId() * -1 else packet.getId())
          }
          null
        }
      }
      for (notifiedId in notifiedIds) {
        firePropertyChange(notifiedId)
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
