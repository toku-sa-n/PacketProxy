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
import java.security.UnrecoverableKeyException
import packetproxy.common.ClientKeyManager
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.PropertyChangeEventType.CLIENT_CERTIFICATES
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.util.errWithStackTrace

/** DAO for ClientCertificate */
class ClientCertificates(
  private val database: Database,
  private val clientKeyManager: ClientKeyManager,
) : PropertyChangeListener {
  private val pcs = PropertyChangeSupport(this)

  private var dao: Dao<ClientCertificate, Int> =
    database.createTable(ClientCertificate::class.java, this)

  init {
    SchemaMigrator.ensureCompatible(database, dao, "clientCertificates") {
      database.dropTable(ClientCertificate::class.java)
      dao = database.createTable(ClientCertificate::class.java, this)
    }
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    pcs.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    pcs.removePropertyChangeListener(listener)
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
        DatabaseMessage.PAUSE,
        DatabaseMessage.RESUME,
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          dao = database.createTable(ClientCertificate::class.java, this)
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(ClientCertificate::class.java, this)
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  fun hasCorrectSecretKey(certificate: ClientCertificate): Boolean =
    try {
      clientKeyManager.setKeyManagers(certificate.getServer(database), certificate.load())
      true
    } catch (_: UnrecoverableKeyException) {
      false
    }

  fun refresh() {
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun create(certificate: ClientCertificate) {
    clientKeyManager.setKeyManagers(certificate.getServer(database), certificate.load())
    certificate.setEnabled()
    dao.createIfNotExists(certificate)
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(certificate: ClientCertificate) {
    dao.delete(certificate)
    clientKeyManager.removeKeyManagers(certificate.getServer(database))
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun update(certificate: ClientCertificate) {
    dao.update(certificate)
    if (certificate.isEnabled())
      clientKeyManager.setKeyManagers(certificate.getServer(database), certificate.load())
    else clientKeyManager.removeKeyManagers(certificate.getServer(database))
    firePropertyChange()
  }

  @Throws(Exception::class) fun query(id: Int): ClientCertificate? = dao.queryForId(id)

  @Throws(Exception::class) fun queryAll(): List<ClientCertificate> = dao.queryBuilder().query()

  @Throws(Exception::class)
  fun queryEnabled(): List<ClientCertificate> =
    dao.queryBuilder().where().eq("enabled", true).query()
}
