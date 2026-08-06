/*
 * Copyright 2026 DeNA Co., Ltd.
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

import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.util.errWithStackTrace

/**
 * Shared PCS + DatabaseMessage handling for DAO managers. Subclasses supply the update event type
 * and reconnect/recreate hooks.
 */
abstract class AbstractDaoManager(protected val database: Database) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)

  protected abstract val updateEventType: PropertyChangeEventType

  protected open fun onReconnect() {}

  protected open fun onRecreate() {}

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  protected fun firePropertyChange(value: Any? = null) {
    changes.firePropertyChange(updateEventType.toString(), null, value)
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (!DATABASE_MESSAGE.matches(evt) && evt.source !is Database) {
      return
    }
    val message = evt.newValue as? DatabaseMessage ?: return
    try {
      when (message) {
        DatabaseMessage.PAUSE,
        DatabaseMessage.RESUME,
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          onReconnect()
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          onRecreate()
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
