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
import packetproxy.model.PropertyChangeEventType.FILTERS
import packetproxy.util.errWithStackTrace

class Filters(private val database: Database) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)

  private var dao: Dao<Filter, Int> = database.createTable(Filter::class.java, this)

  init {
    if (!isLatestVersion()) {
      RecreateTable()
    }
  }

  @Throws(Exception::class)
  fun create(filter: Filter) {
    dao.createIfNotExists(filter)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(filter: Filter) {
    dao.delete(filter)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun deleteByName(name: String) {
    dao.delete(queryByName(name))
    firePropertyChange()
  }

  @Throws(Exception::class) fun query(id: Int): Filter? = dao.queryForId(id)

  @Throws(Exception::class)
  fun queryByName(name: String): List<Filter> = dao.queryBuilder().where().eq("name", name).query()

  @Throws(Exception::class)
  fun queryAll(): List<Filter> = dao.queryBuilder().orderBy("id", false).query()

  @Throws(Exception::class)
  fun update(filter: Filter) {
    dao.update(filter)
    firePropertyChange()
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  private fun firePropertyChange() {
    changes.firePropertyChange(FILTERS.toString(), null, null)
  }

  private fun firePropertyChange(value: Any?) {
    changes.firePropertyChange(FILTERS.toString(), null, value)
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
          dao = database.createTable(Filter::class.java, this)
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(Filter::class.java, this)
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  private fun isLatestVersion(): Boolean {
    val result = dao.queryRaw("SELECT sql FROM sqlite_master WHERE name='filters'").firstResult[0]
    // Logging.log(result);
    return result ==
      "CREATE TABLE `filters` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `name` VARCHAR , `filter` VARCHAR ,  UNIQUE (`name`))"
  }

  @Throws(Exception::class)
  private fun RecreateTable() {
    val option =
      JOptionPane.showConfirmDialog(
        null,
        "filtersテーブルの形式が更新されているため\n現在のテーブルを削除して再起動しても良いですか？",
        "テーブルの更新",
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE,
      )
    if (option == JOptionPane.YES_OPTION) {
      database.dropTable(Filter::class.java)
      dao = database.createTable(Filter::class.java, this)
    }
  }
}
