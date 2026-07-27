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
import com.j256.ormlite.dao.DaoManager
import com.j256.ormlite.jdbc.JdbcConnectionSource
import com.j256.ormlite.logger.LocalLog
import com.j256.ormlite.support.ConnectionSource
import com.j256.ormlite.support.DatabaseConnection
import com.j256.ormlite.table.TableUtils
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import packetproxy.util.Logging.err
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.Logging.log

class Database private constructor() {
  private val changes = PropertyChangeSupport(this)
  private var databaseDir = Paths.get(System.getProperty("user.home") + "/.packetproxy/db")
  private var databasePath = Paths.get(databaseDir.toString() + "/resources.sqlite3")
  private lateinit var source: ConnectionSource

  fun <T> createTable(c: Class<T>, listener: PropertyChangeListener): Dao<T, Int> {
    addPropertyChangeListener(listener)
    return createTable(c)
  }

  fun <T> createTable(c: Class<T>): Dao<T, Int> {
    TableUtils.createTableIfNotExists(source, c)
    return DaoManager.createDao(source, c)
  }

  fun dropFilters() {
    firePropertyChange(DatabaseMessage.DISCONNECT_NOW)
    dropTable(Filter::class.java)
    createTable(Filter::class.java, Filters.getInstance())
    firePropertyChange(DatabaseMessage.RECONNECT)
  }

  fun dropConfigs() {
    firePropertyChange(DatabaseMessage.DISCONNECT_NOW)
    dropTable(ListenPort::class.java)
    dropTable(Server::class.java)
    dropTable(Modification::class.java)
    dropTable(SSLPassThrough::class.java)
    createTable(ListenPort::class.java, ListenPorts.getInstance())
    createTable(Server::class.java, Servers.getInstance())
    createTable(Modification::class.java, Modifications.getInstance())
    createTable(SSLPassThrough::class.java, SSLPassThroughs.getInstance())
    firePropertyChange(DatabaseMessage.RECONNECT)
  }

  fun dropPacketTableFaster() {
    val src =
      Paths.get(instance!!.getDatabasePath().parent.toAbsolutePath().toString() + "/tmp.sqlite3")
    val dst = instance!!.getDatabasePath().toAbsolutePath()
    firePropertyChange(DatabaseMessage.DISCONNECT_NOW)
    source.readWriteConnection.close()
    Files.move(dst, src, StandardCopyOption.REPLACE_EXISTING)
    createDB()
    createTable(Filter::class.java, Filters.getInstance())
    createTable(ListenPort::class.java, ListenPorts.getInstance())
    createTable(Config::class.java, Configs.getInstance())
    createTable(Server::class.java, Servers.getInstance())
    createTable(ClientCertificate::class.java, ClientCertificates.getInstance())
    createTable(InterceptOption::class.java, InterceptOptions.getInstance())
    createTable(Modification::class.java, Modifications.getInstance())
    createTable(SSLPassThrough::class.java, SSLPassThroughs.getInstance())
    createTable(CharSet::class.java, CharSets.getInstance())
    createTable(ResenderPacket::class.java, ResenderPackets.getInstance())
    firePropertyChange(DatabaseMessage.RECREATE)
    migrateTableWithoutHistory(src, dst)
    firePropertyChange(DatabaseMessage.RECONNECT)
    Files.delete(src)
  }

  fun <T> dropTable(c: Class<T>) {
    if (c == Packet::class.java) {
      dropPacketTableFaster()
      return
    }
    TableUtils.dropTable<T, Any>(source, c, true)
  }

  fun openAt(path: String) {
    firePropertyChange(DatabaseMessage.DISCONNECT_NOW)
    if (::source.isInitialized) {
      source.close()
    }
    val dest = FileSystems.getDefault().getPath(path)
    databasePath = dest
    databaseDir = dest.parent ?: dest.parent
    createDB()
    firePropertyChange(DatabaseMessage.RECONNECT)
  }

  fun close() {
    source.close()
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  fun Save(path: String) {
    firePropertyChange(DatabaseMessage.PAUSE)
    Files.copy(
      databasePath,
      FileSystems.getDefault().getPath(path),
      StandardCopyOption.REPLACE_EXISTING,
    )
    firePropertyChange(DatabaseMessage.RESUME)
  }

  fun Load(path: String) {
    firePropertyChange(DatabaseMessage.DISCONNECT_NOW)
    source.close()
    val dest = FileSystems.getDefault().getPath(databaseDir.toString() + "/resources_temp.sqlite3")
    Files.copy(FileSystems.getDefault().getPath(path), dest, StandardCopyOption.REPLACE_EXISTING)
    databasePath = dest
    source = JdbcConnectionSource(databaseURL)
    firePropertyChange(DatabaseMessage.RECONNECT)
  }

  fun saveWithoutLog(path: String) {
    firePropertyChange(DatabaseMessage.PAUSE)
    val dest = FileSystems.getDefault().getPath(path)
    Files.copy(databasePath, dest, StandardCopyOption.REPLACE_EXISTING)
    val newDb = JdbcConnectionSource("jdbc:sqlite:$dest")
    newDb.readWriteConnection.apply {
      executeStatement("delete from packets", DatabaseConnection.DEFAULT_RESULT_FLAGS)
      close()
    }
    newDb.close()
    firePropertyChange(DatabaseMessage.RESUME)
  }

  fun LoadAndReplace(path: String) {
    firePropertyChange(DatabaseMessage.DISCONNECT_NOW)
    source.close()
    Files.move(
      FileSystems.getDefault().getPath(path),
      databasePath,
      StandardCopyOption.REPLACE_EXISTING,
    )
    source = JdbcConnectionSource(databaseURL)
    firePropertyChange(DatabaseMessage.RECONNECT)
  }

  fun getDatabasePath(): Path = databasePath

  fun isAlertFileSize(): Boolean =
    File(databasePath.toString()).length() / 1048576 > ALERT_DB_FILE_SIZE_MB

  private fun createDB() {
    if (!Files.exists(databaseDir)) {
      log("%s directory is not found...", databaseDir.toAbsolutePath())
      log("creating the directory...")
      Files.createDirectories(databaseDir)
      log("success!")
    } else if (!Files.isDirectory(databaseDir)) {
      err("%s file is not directory...", databaseDir.toAbsolutePath())
      err("Must be a directory")
      System.exit(1)
    }
    System.setProperty(LocalLog.LOCAL_LOG_LEVEL_PROPERTY, "error")
    source = JdbcConnectionSource(databaseURL)
    source.readWriteConnection.executeStatement(
      "pragma auto_vacuum = full",
      DatabaseConnection.DEFAULT_RESULT_FLAGS,
    )
  }

  private fun firePropertyChange(message: DatabaseMessage) {
    changes.firePropertyChange(PropertyChangeEventType.DATABASE_MESSAGE.toString(), null, message)
  }

  private val databaseURL: String
    get() = "jdbc:sqlite:$databasePath"

  enum class DatabaseMessage {
    PAUSE,
    RESUME,
    DISCONNECT_NOW,
    RECONNECT,
    RECREATE,
  }

  companion object {
    private const val ALERT_DB_FILE_SIZE_MB = 1536
    private var instance: Database? = null

    @JvmStatic
    fun getInstance(): Database {
      if (instance == null) {
        instance = Database()
        instance!!.createDB()
      }
      return instance!!
    }

    private fun migrateTableWithoutHistory(srcDBPath: Path, dstDBPath: Path) {
      try {
        val source: ConnectionSource = JdbcConnectionSource("jdbc:sqlite:$srcDBPath")
        val conn = source.readWriteConnection
        conn.executeStatement(
          "attach database '${dstDBPath.toAbsolutePath()}' as 'dstDB'",
          DatabaseConnection.DEFAULT_RESULT_FLAGS,
        )
        conn.executeStatement(
          "attach database '${srcDBPath.toAbsolutePath()}' as 'srcDB'",
          DatabaseConnection.DEFAULT_RESULT_FLAGS,
        )
        val queries =
          arrayOf(
            "DELETE FROM dstDB.interceptOptions",
            "DELETE FROM dstDB.charsets",
            "INSERT OR REPLACE INTO dstDB.filters (id, name, filter) SELECT id, name, filter FROM srcDB.filters",
            "INSERT OR REPLACE INTO dstDB.listenports (id, enabled, ca_name, port, type, server_id) SELECT id, enabled, ca_name, port, type, server_id FROM srcDB.listenports",
            "INSERT OR REPLACE INTO dstDB.configs (key, value) SELECT key, value FROM srcDB.configs",
            "INSERT OR REPLACE INTO dstDB.servers (id, ip, port, encoder, use_ssl, resolved_by_dns, resolved_by_dns6, http_proxy, comment) SELECT id, ip, port, encoder, use_ssl, resolved_by_dns, resolved_by_dns6, http_proxy, comment FROM srcDB.servers",
            "INSERT OR REPLACE INTO dstDB.clientCertificates (id, enabled, type, serverId, subject, issuer, path, storePassword, keyPassword) SELECT id, enabled, type, serverId, subject, issuer, path, storePassword, keyPassword FROM srcDB.clientCertificates",
            "INSERT OR REPLACE INTO dstDB.interceptOptions (id, enabled, direction, type, relationship, method, pattern, server_id) SELECT id, enabled, direction, type, relationship, method, pattern, server_id FROM srcDB.interceptOptions",
            "INSERT OR REPLACE INTO dstDB.modifications (id, enabled, server_id, direction, pattern, method, replaced) SELECT id, enabled, server_id, direction, pattern, method, replaced FROM srcDB.modifications",
            "INSERT OR REPLACE INTO dstDB.sslpassthroughs (id, enabled, server_name, listen_port) SELECT id, enabled, server_name, listen_port FROM srcDB.sslpassthroughs",
            "INSERT OR REPLACE INTO dstDB.charsets (id, charsetname) SELECT id, charsetname FROM srcDB.charsets",
            "INSERT OR REPLACE INTO dstDB.resender_packets (id, resends_index, resend_index, direction, data, listen_port, client_ip, client_port, server_ip, server_port, server_name, use_ssl, encoder_name, alpn, auto_modified, conn, `group`) SELECT id, resends_index, resend_index, direction, data, listen_port, client_ip, client_port, server_ip, server_port, server_name, use_ssl, encoder_name, alpn, auto_modified, conn, `group` FROM srcDB.resender_packets",
          )
        queries.forEach {
          try {
            conn.executeStatement(it, DatabaseConnection.DEFAULT_RESULT_FLAGS)
          } catch (e: Exception) {
            log("Database format may have been changed. Simply ignore this type of errors.")
            log("[Error] %s", it)
          }
        }
        conn.close()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }
}
