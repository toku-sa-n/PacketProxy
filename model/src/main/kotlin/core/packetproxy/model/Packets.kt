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
import com.j256.ormlite.stmt.SelectArg
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import packetproxy.common.Logger
import packetproxy.model.Database.DatabaseMessage
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class Packets(
  private val database: Database,
  restore: Boolean,
  private val configs: Configs? = null,
) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)
  private var dao: Dao<Packet, Int> = database.createTable(Packet::class.java)
  private val executor = Executors.newSingleThreadExecutor()
  private val ftsExecutor = Executors.newSingleThreadExecutor()
  private val pendingUpdates = LinkedHashMap<String, Packet>()
  private val updateScheduled = AtomicBoolean(false)
  private val pruneScheduled = AtomicBoolean(false)

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
    packet.compactForPersist()
    synchronized(dao) { dao.createIfNotExists(packet) }
    scheduleFts(packet)
    firePropertyChange()
    scheduleAutoPrune()
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
    packet.compactForPersist()
    val id = packet.getId()
    if (id > 0) {
      synchronized(dao) { dao.update(packet) }
      scheduleFts(packet)
      firePropertyChange(id)
      scheduleAutoPrune()
      return
    }
    val status = synchronized(dao) { dao.createOrUpdate(packet) }
    scheduleFts(packet)
    firePropertyChange(if (status.isCreated) packet.getId() * -1 else packet.getId())
    scheduleAutoPrune()
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
          updateColumnValue("content_type", SelectArg(contentType))
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
          updateColumnValue("color", SelectArg(color))
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

  /**
   * Update persisted summary columns without rewriting BLOB columns. No-op when id <= 0. When
   * [notify] is false, skips [firePropertyChange] (for bulk History restore backfill).
   */
  fun updatePersistedSummaries(
    id: Int,
    summarizedRequest: String?,
    summarizedResponse: String?,
    displayLength: Int,
    notify: Boolean = true,
  ) {
    if (id <= 0) {
      return
    }
    synchronized(dao) {
      dao
        .updateBuilder()
        .apply {
          updateColumnValue("summarized_request", SelectArg(summarizedRequest))
          updateColumnValue("summarized_response", SelectArg(summarizedResponse))
          updateColumnValue("display_length", displayLength)
          where().eq("id", id)
        }
        .update()
    }
    if (notify) {
      firePropertyChange(id)
    }
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
      .selectColumns(*METADATA_COLUMNS)
      .offset(offset)
      .limit(limit)
      .orderBy("id", ascending)
      .query()

  fun queryByIdMetadata(id: Int): Packet? =
    dao.queryBuilder().selectColumns(*METADATA_COLUMNS).where().eq("id", id).queryForFirst()

  fun queryAllMetadata(): List<Packet> =
    dao.queryBuilder().selectColumns(*METADATA_COLUMNS).orderBy("id", true).query()

  fun queryAll(): List<Packet> = dao.queryBuilder().orderBy("id", true).query()

  /** Invokes [action] for each page of full packets (including BLOBs). */
  fun forEachPage(pageSize: Long = 100L, action: (List<Packet>) -> Unit) {
    var offset = 0L
    while (true) {
      val page = queryPage(offset, pageSize, true)
      if (page.isEmpty()) {
        return
      }
      action(page)
      offset += page.size
    }
  }

  /** Invokes [action] for each page of metadata-only packets. */
  fun forEachMetadataPage(pageSize: Long = 500L, action: (List<Packet>) -> Unit) {
    var offset = 0L
    while (true) {
      val page = queryPageMetadata(offset, pageSize, true)
      if (page.isEmpty()) {
        return
      }
      action(page)
      offset += page.size
    }
  }

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

  fun outputAllPackets(filename: String): String {
    val outFile = java.io.File(filename)
    outFile.parentFile?.mkdirs()
    outFile.bufferedWriter().use { writer ->
      forEachPage(50L) { page -> writer.write(Logger(page).toLogString()) }
    }
    return filename
  }

  fun isEmpty(): Boolean = dao.queryBuilder().limit(1L).query().isEmpty()

  /** Deletes up to [limit] oldest packets by id. Returns number deleted. */
  fun deleteOldest(limit: Int): Int {
    if (limit <= 0) {
      return 0
    }
    val oldest =
      dao.queryBuilder().selectColumns("id").orderBy("id", true).limit(limit.toLong()).query()
    if (oldest.isEmpty()) {
      return 0
    }
    synchronized(dao) {
      for (packet in oldest) {
        val id = packet.getId()
        dao.deleteById(id)
        deleteFts(id)
      }
    }
    firePropertyChange()
    return oldest.size
  }

  fun handleDatabaseMessage(message: DatabaseMessage) {
    try {
      when (message) {
        DatabaseMessage.PAUSE,
        DatabaseMessage.RESUME,
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          dao = database.createTable(Packet::class.java)
          SchemaMigrator.ensureColumns(dao)
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

  private fun scheduleFts(packet: Packet) {
    val id = packet.getId()
    if (id <= 0) {
      return
    }
    // Snapshot fields needed for FTS so later in-memory mutation does not affect indexing.
    val contentType = packet.getContentType()
    val group = packet.getGroup()
    val bodyBytes =
      when {
        packet.getDecodedData().isNotEmpty() -> packet.getDecodedData().copyOf()
        packet.getModifiedData().isNotEmpty() -> packet.getModifiedData().copyOf()
        else -> packet.getReceivedData().copyOf()
      }
    ftsExecutor.execute {
      try {
        synchronized(dao) {
          deleteFts(id)
          if (!shouldSkipFts(contentType) && bodyBytes.isNotEmpty()) {
            val indexedBytes =
              if (bodyBytes.size > FTS_BODY_MAX_BYTES) bodyBytes.copyOf(FTS_BODY_MAX_BYTES)
              else bodyBytes
            val body =
              try {
                String(indexedBytes, Charsets.UTF_8)
              } catch (_: Exception) {
                String(indexedBytes, Charsets.ISO_8859_1)
              }
            dao.executeRaw(
              "INSERT INTO packets_fts(packet_id, group_id, body) VALUES (?, ?, ?)",
              id.toString(),
              group.toString(),
              body.take(FTS_BODY_MAX_CHARS),
            )
          }
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  private fun shouldSkipFts(contentType: String?): Boolean {
    if (contentType.isNullOrEmpty()) {
      return false
    }
    val lower = contentType.lowercase()
    return lower.startsWith("image/") ||
      lower.startsWith("audio/") ||
      lower.startsWith("video/") ||
      lower == "application/octet-stream" ||
      lower.startsWith("application/pdf") ||
      lower.startsWith("application/zip") ||
      lower.startsWith("application/gzip")
  }

  private fun deleteFts(id: Int) {
    if (id <= 0) {
      return
    }
    dao.executeRaw("DELETE FROM packets_fts WHERE packet_id = ?", id.toString())
  }

  private fun queryFts(search: String): List<Packet> {
    if (search.isEmpty()) {
      return emptyList()
    }
    // FTS5 MATCH is case-insensitive with unicode61; quote the phrase for literal match.
    val escaped = search.replace("\"", "\"\"")
    val match = "\"$escaped\""
    val rows =
      dao.queryRaw("SELECT group_id, packet_id FROM packets_fts WHERE packets_fts MATCH ?", match)
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
      val ftsTargets = ArrayList<Packet>(batch.size)
      synchronized(dao) {
        dao.callBatchTasks {
          for (packet in batch) {
            packet.compactForPersist()
            val id = packet.getId()
            if (id > 0) {
              dao.update(packet)
              ftsTargets.add(packet)
              notifiedIds.add(id)
              continue
            }
            val status = dao.createOrUpdate(packet)
            ftsTargets.add(packet)
            notifiedIds.add(if (status.isCreated) packet.getId() * -1 else packet.getId())
          }
          null
        }
      }
      for (packet in ftsTargets) {
        scheduleFts(packet)
      }
      for (notifiedId in notifiedIds) {
        firePropertyChange(notifiedId)
      }
    }
  }

  private fun scheduleAutoPrune() {
    val cfg = configs ?: return
    if (!ConfigBoolean(cfg, KEY_AUTO_PRUNE_ENABLED).getState()) {
      return
    }
    if (!pruneScheduled.compareAndSet(false, true)) {
      return
    }
    executor.execute {
      try {
        runAutoPrune(cfg)
      } catch (e: Exception) {
        errWithStackTrace(e)
      } finally {
        pruneScheduled.set(false)
      }
    }
  }

  private fun runAutoPrune(cfg: Configs) {
    val maxPackets = ConfigInteger(cfg, KEY_AUTO_PRUNE_MAX_PACKETS, "100000").getInteger()
    val maxDbMb = ConfigInteger(cfg, KEY_AUTO_PRUNE_MAX_DB_MB, "1024").getInteger()
    var guard = 0
    while (guard++ < 100) {
      val count = countOf()
      val dbMb = database.getDatabasePath().toFile().length() / 1048576
      val overCount = maxPackets > 0 && count > maxPackets
      val overSize = maxDbMb > 0 && dbMb > maxDbMb
      if (!overCount && !overSize) {
        return
      }
      val excess =
        when {
          overCount -> (count - maxPackets).toInt().coerceAtLeast(1)
          else -> PRUNE_BATCH_SIZE
        }
      val deleted = deleteOldest(minOf(excess, PRUNE_BATCH_SIZE))
      if (deleted <= 0) {
        return
      }
      log("auto-prune: deleted %d oldest packets (count=%d, dbMb=%d)", deleted, count, dbMb)
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
        scheduleAutoPrune()
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

  companion object {
    const val KEY_AUTO_PRUNE_ENABLED = "history.auto_prune.enabled"
    const val KEY_AUTO_PRUNE_MAX_PACKETS = "history.auto_prune.max_packets"
    const val KEY_AUTO_PRUNE_MAX_DB_MB = "history.auto_prune.max_db_mb"
    private const val FTS_BODY_MAX_BYTES = 64 * 1024
    private const val FTS_BODY_MAX_CHARS = 64_000
    private const val PRUNE_BATCH_SIZE = 500
    private val METADATA_COLUMNS =
      arrayOf(
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
        "blob_flags",
      )
  }
}
