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
import packetproxy.model.PropertyChangeEventType.CHARSET_UPDATED
import packetproxy.util.Logging.errWithStackTrace

class CharSets private constructor() : PropertyChangeListener {
  private val pcs = PropertyChangeSupport(this)

  private val defaultCharSetList =
    listOf("UTF-8", "Shift_JIS", "x-euc-jp-linux", "ISO-2022-JP", "ISO-8859-1")

  private var database: Database = Database.getInstance()
  private var dao: Dao<CharSet, Int> = database.createTable(CharSet::class.java, this)

  @Throws(Exception::class)
  private fun setDefaultCharSetIfNotFound() {
    if (dao.queryBuilder().query().size == 0) {
      for (charSetName in defaultCharSetList) {
        if (null == queryByCharSetName(charSetName)) {
          create(CharSet(charSetName))
        }
      }
    }
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    pcs.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    pcs.removePropertyChangeListener(listener)
  }

  @Throws(Exception::class)
  fun create(charset: CharSet) {
    dao.createIfNotExists(charset)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(charset: CharSet) {
    dao.delete(charset)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun queryByString(str: String): CharSet? {
    val all = this.queryAll()
    for (server in all) {
      if (server.toString() == str) {
        return server
      }
    }
    return null
  }

  @Throws(Exception::class)
  fun queryByCharSetName(charsetname: String): CharSet? =
    dao.queryBuilder().where().eq("charsetname", charsetname).queryForFirst()

  @Throws(Exception::class) fun query(id: Int): CharSet? = dao.queryForId(id)

  @Throws(Exception::class)
  fun queryAll(): List<CharSet> {
    setDefaultCharSetIfNotFound()
    return dao.queryBuilder().orderBy("charsetname", true).query()
  }

  @Throws(Exception::class)
  fun update(charsets: List<CharSet>) {
    for (charset in charsets) {
      dao.update(charset)
      firePropertyChange()
    }
  }

  @Throws(Exception::class)
  fun update(charset: CharSet) {
    dao.update(charset)
    firePropertyChange()
  }

  private fun firePropertyChange() {
    pcs.firePropertyChange(CHARSET_UPDATED.toString(), null, null)
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
          database = Database.getInstance()
          dao = database.createTable(CharSet::class.java, this)
          firePropertyChange()
        }
        DatabaseMessage.RECREATE -> {
          database = Database.getInstance()
          dao = database.createTable(CharSet::class.java, this)
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  companion object {
    private var instance: CharSets? = null

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): CharSets {
      if (instance == null) {
        instance = CharSets()
      }
      return instance!!
    }
  }
}
