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

import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import packetproxy.model.PropertyChangeEventType.INTERCEPT_DATA
import packetproxy.model.PropertyChangeEventType.INTERCEPT_MODE

class InterceptModel() {
  private val pcs = PropertyChangeSupport(this)

  private var data: ByteArray? = null
  private var client_packet: Packet? = null
  private var server_packet: Packet? = null
  private var intercept_mode = false

  init {
    clear()
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    pcs.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    pcs.removePropertyChangeListener(listener)
  }

  fun enableInterceptMode() {
    val oldValue = this.intercept_mode
    this.intercept_mode = true
    pcs.firePropertyChange(INTERCEPT_MODE.toString(), oldValue, this.intercept_mode)
  }

  fun disableInterceptMode() {
    val oldValue = this.intercept_mode
    this.intercept_mode = false
    pcs.firePropertyChange(INTERCEPT_MODE.toString(), oldValue, this.intercept_mode)
  }

  fun isInterceptEnabled(): Boolean = this.intercept_mode

  fun setData(data: ByteArray?, client_packet: Packet?, server_packet: Packet?) {
    val oldData = this.data
    this.data = data
    this.client_packet = client_packet
    this.server_packet = server_packet
    pcs.firePropertyChange(INTERCEPT_DATA.toString(), oldData, this.data)
  }

  fun getData(): ByteArray? = data

  fun getClientPacket(): Packet? = this.client_packet

  fun getServerPacket(): Packet? = this.server_packet

  fun clearData() {
    val oldData = this.data
    clear()
    pcs.firePropertyChange(INTERCEPT_DATA.toString(), oldData, this.getData())
  }

  private fun clear() {
    this.data = null
    this.client_packet = null
    this.server_packet = null
  }
}
