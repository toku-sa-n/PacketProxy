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
import java.nio.file.Files
import java.nio.file.Paths
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.PropertyChangeEventType.RESOLUTIONS_UPDATED
import packetproxy.util.PacketProxyUtility
import packetproxy.util.errWithStackTrace

class Resolutions(private val database: Database) : PropertyChangeListener {
  private val pcs = PropertyChangeSupport(this)

  private var dao: Dao<Resolution, Int> = database.createTable(Resolution::class.java, this)
  private var cache = DaoQueryCache<Resolution>()

  init {
    if (dao.countOf() == 0L) {
      setResolutionsBySystem()
    }
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    pcs.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    pcs.removePropertyChangeListener(listener)
  }

  @Throws(Exception::class)
  fun setResolutionsBySystem() {
    val fileLines: List<String>
    if (PacketProxyUtility().isWindows()) {
      fileLines = Files.readAllLines(Paths.get("C:\\Windows\\System32\\drivers\\etc\\hosts"))
    } else {
      fileLines = Files.readAllLines(Paths.get("/etc/hosts"))
    }
    fileLines.stream().forEach { line ->
      if (!(line.startsWith("#"))) {
        try {
          val parts = line.split("[\\s]+".toRegex()).toTypedArray()
          if (parts.size >= 2) {
            val ip = parts[0]
            val hostname = parts[1]
            create(Resolution(ip, hostname))
          }
        } catch (e1: Exception) {
          errWithStackTrace(e1)
        }
      }
    }
  }

  @Throws(Exception::class)
  fun create(resolution: Resolution) {
    dao.createIfNotExists(resolution)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(resolution: Resolution) {
    dao.delete(resolution)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun queryByString(str: String): Resolution? {
    val all = this.queryAll()
    for (resolution in all) {
      if (resolution.toString() == str) {
        return resolution
      }
    }
    return null
  }

  @Throws(Exception::class)
  fun queryByHostName(hostname: String): Resolution? {
    val ret = cache.query("queryByHostName", hostname)
    if (ret != null) {
      return ret[0]
    }

    val resolution = dao.queryBuilder().where().eq("ip", hostname).queryForFirst()

    cache.set("queryByHostName", hostname, resolution)
    return resolution
  }

  @Throws(Exception::class)
  fun query(id: Int): Resolution? {
    val ret = cache.query("query", id)
    if (ret != null) {
      return ret[0]
    }

    val resolution = dao.queryForId(id)

    cache.set("query", id, resolution)
    return resolution
  }

  @Throws(Exception::class)
  fun queryAll(): List<Resolution> {
    var ret = cache.query("queryAll", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().orderBy("ip", true).query()

    cache.set("queryAll", 0, ret)
    return ret
  }

  @Throws(Exception::class)
  fun queryEnabled(): List<Resolution> {
    var ret = cache.query("queryEnabled", 0)
    if (ret != null) {
      return ret
    }

    ret = dao.queryBuilder().where().eq("enabled", true).query()

    cache.set("queryEnabled", 0, ret)
    return ret
  }

  @Throws(Exception::class)
  fun update(resolution: Resolution) {
    dao.update(resolution)
    cache.clear()
    firePropertyChange()
  }

  private fun firePropertyChange() {
    pcs.firePropertyChange(RESOLUTIONS_UPDATED.toString(), null, null)
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
          dao = database.createTable(Resolution::class.java, this)
          cache.clear()
          firePropertyChange()
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(Resolution::class.java, this)
          cache.clear()
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
