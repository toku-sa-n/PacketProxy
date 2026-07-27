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
import packetproxy.common.ClientKeyManager
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.PropertyChangeEventType.CLIENT_CERTIFICATES
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.util.Logging.errWithStackTrace

/** DAO for ClientCertificate */
class ClientCertificates private constructor() : PropertyChangeListener {
  private val pcs = PropertyChangeSupport(this)

  private var database: Database = Database.getInstance()
  private var dao: Dao<ClientCertificate, Int> =
    database.createTable(ClientCertificate::class.java, this)
  private var servers: Servers = Servers.getInstance()

  init {
    if (!isLatestVersion()) {
      RecreateTable()
    }
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    pcs.addPropertyChangeListener(listener)
    servers.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    pcs.removePropertyChangeListener(listener)
    servers.removePropertyChangeListener(listener)
  }

  fun firePropertyChange() {
    firePropertyChange(null)
  }

  fun firePropertyChange(arg: Any?) {
    pcs.firePropertyChange(CLIENT_CERTIFICATES.toString(), null, arg)
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
          database = Database.getInstance()
          dao = database.createTable(ClientCertificate::class.java, this)
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          database = Database.getInstance()
          dao = database.createTable(ClientCertificate::class.java, this)
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  fun hasCorrectSecretKey(certificate: ClientCertificate): Boolean {
    try {
      ClientKeyManager.setKeyManagers(certificate.getServer(), certificate.load())
      return true
    } catch (keyException: java.security.UnrecoverableKeyException) {
      return false
    }
  }

  fun refresh() {
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun create(certificate: ClientCertificate) {
    ClientKeyManager.setKeyManagers(certificate.getServer(), certificate.load())
    certificate.setEnabled()
    dao.createIfNotExists(certificate)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(certificate: ClientCertificate) {
    dao.delete(certificate)
    ClientKeyManager.removeKeyManagers(certificate.getServer())
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun update(certificate: ClientCertificate) {
    dao.update(certificate)
    if (certificate.isEnabled())
      ClientKeyManager.setKeyManagers(certificate.getServer(), certificate.load())
    else ClientKeyManager.removeKeyManagers(certificate.getServer())
    firePropertyChange()
  }

  @Throws(Exception::class) fun query(id: Int): ClientCertificate? = dao.queryForId(id)

  @Throws(Exception::class) fun queryAll(): List<ClientCertificate> = dao.queryBuilder().query()

  @Throws(Exception::class)
  fun queryEnabled(): List<ClientCertificate> =
    dao.queryBuilder().where().eq("enabled", true).query()

  @Throws(Exception::class)
  private fun isLatestVersion(): Boolean {
    val result =
      dao.queryRaw("SELECT sql FROM sqlite_master WHERE name='clientCertificates'").firstResult[0]
    return result ==
      "CREATE TABLE `clientCertificates` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `enabled` BOOLEAN , `type` VARCHAR , `serverId` INTEGER , `subject` VARCHAR , `issuer` VARCHAR , `path` VARCHAR , `storePassword` VARCHAR , `keyPassword` VARCHAR , UNIQUE (`type`,`serverId`,`path`) )"
  }

  @Throws(Exception::class)
  private fun RecreateTable() {
    val option =
      JOptionPane.showConfirmDialog(
        null,
        "client_certificatesテーブルの形式が更新されているため\n現在のテーブルを削除して再起動しても良いですか？",
        "テーブルの更新",
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE,
      )
    if (option == JOptionPane.YES_OPTION) {
      database.dropTable(ClientCertificate::class.java)
      dao = database.createTable(ClientCertificate::class.java, this)
    }
  }

  companion object {
    private var instance: ClientCertificates? = null

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): ClientCertificates {
      if (instance == null) {
        instance = ClientCertificates()
      }
      return instance!!
    }
  }
}
