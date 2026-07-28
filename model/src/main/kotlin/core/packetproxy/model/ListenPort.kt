/*
 * Copyright 2019,2022 DeNA Co., Ltd.
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

import com.j256.ormlite.field.DatabaseField
import com.j256.ormlite.table.DatabaseTable
import java.util.Optional
import packetproxy.model.CAs.CA

@DatabaseTable(tableName = "listenports")
open class ListenPort {
  enum class Protocol {
    TCP,
    UDP,
  }

  enum class TYPE {
    HTTP_PROXY,
    FORWARDER,
    SSL_FORWARDER,
    UDP_FORWARDER,
    SSL_TRANSPARENT_PROXY,
    HTTP_TRANSPARENT_PROXY,
    XMPP_SSL_FORWARDER,
    QUIC_FORWARDER,
    QUIC_TRANSPARENT_PROXY;

    fun isForwarder(): Boolean =
      this == FORWARDER ||
        this == SSL_FORWARDER ||
        this == UDP_FORWARDER ||
        this == XMPP_SSL_FORWARDER ||
        this == QUIC_FORWARDER

    fun getProtocol(): Protocol =
      if (this == QUIC_FORWARDER || this == QUIC_TRANSPARENT_PROXY || this == UDP_FORWARDER) {
        Protocol.UDP
      } else {
        Protocol.TCP
      }
  }

  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField private var enabled: Boolean? = null

  @field:DatabaseField private var ca_name: String? = null

  @field:DatabaseField(uniqueCombo = true) private var port = 0

  @field:DatabaseField(uniqueCombo = true) private var type: TYPE? = null

  @field:DatabaseField(uniqueCombo = true) private var server_id = 0

  private var protocol: Protocol? = null

  constructor()

  constructor(port: Int, type: TYPE) {
    this.enabled = false
    this.port = port
    this.type = type
    this.server_id = 0
    this.ca_name = "PacketProxy CA"
    this.protocol = type.getProtocol()
  }

  constructor(port: Int, type: TYPE, server: Server?, ca_name: String) {
    this.enabled = false
    this.port = port
    this.type = type
    this.server_id = if (server != null) server.getId() else 0
    this.ca_name = ca_name
    this.protocol = type.getProtocol()
  }

  fun isEnabled(): Boolean = this.enabled!!

  fun setEnabled() {
    this.enabled = true
  }

  fun setDisabled() {
    this.enabled = false
  }

  fun setCA(ca: CA) {
    this.ca_name = ca.getName()
  }

  fun getCA(): Optional<CA> = ModelServices.require().caFactory.find(this.ca_name)

  fun getPort(): Int = this.port

  fun setPort(port: Int) {
    this.port = port
  }

  fun getServerId(): Int = this.server_id

  fun setServerId(server_id: Int) {
    this.server_id = server_id
  }

  @Throws(Exception::class)
  open fun getServer(database: Database): Server? =
    database.createTable(Server::class.java).queryForId(this.server_id)

  fun getProtocol(): Protocol {
    if (this.protocol == null) {
      this.protocol = this.type!!.getProtocol()
    }
    return this.protocol!!
  }

  fun getProtoPort(): String = String.format("%s %s", getProtocol(), getPort())

  fun getType(): TYPE? = this.type

  fun setType(type: TYPE) {
    this.type = type
  }

  fun getId(): Int = id

  fun setId(id: Int) {
    this.id = id
  }

  override fun hashCode(): Int = this.getId()

  fun equals(obj: ListenPort): Boolean = this.getId() == obj.getId()
}
