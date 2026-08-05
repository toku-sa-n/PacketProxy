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

import com.j256.ormlite.field.DataType
import com.j256.ormlite.field.DatabaseField
import com.j256.ormlite.table.DatabaseTable
import java.net.InetSocketAddress
import java.util.Date

@DatabaseTable(tableName = "packets")
class Packet : PacketInfo {
  enum class Direction {
    SERVER,
    CLIENT,
  }

  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField(dataType = DataType.ENUM_STRING) private var direction: Direction? = null

  @field:DatabaseField(dataType = DataType.BYTE_ARRAY) private var decoded_data: ByteArray? = null

  @field:DatabaseField(dataType = DataType.BYTE_ARRAY) private var modified_data: ByteArray? = null

  @field:DatabaseField(dataType = DataType.BYTE_ARRAY) private var sent_data: ByteArray? = null

  @field:DatabaseField(dataType = DataType.BYTE_ARRAY) private var received_data: ByteArray? = null

  // Bit flags for stage BLOB aliasing (empty stored BLOB + flag means "same as prior stage").
  @field:DatabaseField private var blob_flags = 0

  @field:DatabaseField private var listen_port = 0

  @field:DatabaseField private var client_ip: String? = null

  @field:DatabaseField private var client_port = 0

  @field:DatabaseField private var server_ip: String? = null

  @field:DatabaseField private var server_name: String? = null

  @field:DatabaseField private var server_port = 0

  @field:DatabaseField private var use_ssl = false

  @field:DatabaseField private var content_type: String? = null

  @field:DatabaseField private var encoder_name: String? = null

  @field:DatabaseField private var alpn: String? = null

  @field:DatabaseField private var modified = false

  @field:DatabaseField private var resend = false

  @field:DatabaseField(dataType = DataType.DATE_LONG) private var date: Date? = null

  @field:DatabaseField private var conn = 0

  @field:DatabaseField private var group = 0L

  @field:DatabaseField private var color: String? = null

  @field:DatabaseField private var job_id: String? = null

  @field:DatabaseField private var temporary_id: String? = null

  @field:DatabaseField private var summarized_request: String? = null

  @field:DatabaseField private var summarized_response: String? = null

  @field:DatabaseField private var display_length = 0

  constructor()

  constructor(
    listen_port: Int,
    client_addr: InetSocketAddress,
    server_addr: InetSocketAddress,
    server_name: String,
    use_ssl: Boolean,
    encoder: String,
    alpn: String,
    dir: Direction,
    conn: Int,
    group: Long,
  ) {
    initialize(
      listen_port,
      client_addr.address.hostAddress,
      client_addr.port,
      server_addr.address.hostAddress,
      server_addr.port,
      server_name,
      use_ssl,
      encoder,
      alpn,
      dir,
      conn,
      group,
    )
  }

  constructor(
    listen_port: Int,
    client_ip: String,
    client_port: Int,
    server_ip: String,
    server_port: Int,
    server_name: String,
    use_ssl: Boolean,
    encoder: String,
    alpn: String,
    dir: Direction,
    conn: Int,
    group: Long,
  ) {
    initialize(
      listen_port,
      client_ip,
      client_port,
      server_ip,
      server_port,
      server_name,
      use_ssl,
      encoder,
      alpn,
      dir,
      conn,
      group,
    )
  }

  override fun getDirection(): Direction? = direction

  override fun getId(): Int = id

  fun getOneShotPacket(data: ByteArray): OneShotPacket =
    OneShotPacket(
      getId(),
      getListenPort(),
      getClient(),
      getServer(),
      getServerName()!!,
      getUseSSL(),
      data,
      getEncoder()!!,
      getAlpn()!!,
      getDirection()!!,
      getConn(),
      getGroup(),
      getJobId(),
      getTemporaryId(),
    )

  fun setModifiedData(data: ByteArray) {
    modified_data = data
    blob_flags = blob_flags and FLAG_MODIFIED_ALIASES_DECODED.inv()
  }

  fun getModifiedData(): ByteArray {
    if ((blob_flags and FLAG_MODIFIED_ALIASES_DECODED) != 0) {
      return getDecodedData()
    }
    return modified_data ?: byteArrayOf()
  }

  fun getOneShotFromModifiedData(): OneShotPacket = getOneShotPacket(getModifiedData())

  fun setSentData(data: ByteArray) {
    sent_data = data
    blob_flags = blob_flags and FLAG_SENT_ALIASES_MODIFIED.inv()
  }

  fun getSentData(): ByteArray {
    if ((blob_flags and FLAG_SENT_ALIASES_MODIFIED) != 0) {
      return getModifiedData()
    }
    return sent_data ?: byteArrayOf()
  }

  fun setReceivedData(data: ByteArray) {
    received_data = data
  }

  fun getReceivedData(): ByteArray = received_data ?: byteArrayOf()

  fun getOneShotFromReceivedData(): OneShotPacket = getOneShotPacket(getReceivedData())

  fun setDecodedData(data: ByteArray) {
    decoded_data = data
    blob_flags = blob_flags and FLAG_DECODED_ALIASES_RECEIVED.inv()
  }

  fun getDecodedData(): ByteArray {
    if ((blob_flags and FLAG_DECODED_ALIASES_RECEIVED) != 0) {
      return getReceivedData()
    }
    return decoded_data ?: byteArrayOf()
  }

  fun getOneShotFromDecodedData(): OneShotPacket = getOneShotPacket(getDecodedData())

  /**
   * Collapses identical stage BLOBs before DB write. Empty stored arrays + [blob_flags] mean the
   * stage aliases the previous one; getters resolve the chain.
   */
  fun compactForPersist() {
    val received = received_data ?: byteArrayOf()
    var flags = 0

    val decoded = decoded_data ?: byteArrayOf()
    if (decoded.isNotEmpty() && decoded.contentEquals(received)) {
      decoded_data = byteArrayOf()
      flags = flags or FLAG_DECODED_ALIASES_RECEIVED
    }
    val effectiveDecoded =
      if ((flags and FLAG_DECODED_ALIASES_RECEIVED) != 0) received
      else (decoded_data ?: byteArrayOf())

    val modified = modified_data ?: byteArrayOf()
    if (modified.isNotEmpty() && modified.contentEquals(effectiveDecoded)) {
      modified_data = byteArrayOf()
      flags = flags or FLAG_MODIFIED_ALIASES_DECODED
    }
    val effectiveModified =
      if ((flags and FLAG_MODIFIED_ALIASES_DECODED) != 0) effectiveDecoded
      else (modified_data ?: byteArrayOf())

    val sent = sent_data ?: byteArrayOf()
    if (sent.isNotEmpty() && sent.contentEquals(effectiveModified)) {
      sent_data = byteArrayOf()
      flags = flags or FLAG_SENT_ALIASES_MODIFIED
    }
    blob_flags = flags
  }

  fun getBlobFlags(): Int = blob_flags

  fun setModified() {
    modified = true
  }

  fun getModified(): Boolean = modified

  fun setResend() {
    resend = true
  }

  fun getResend(): Boolean = resend

  override fun getListenPort(): Int = listen_port

  override fun getClientIP(): String? = client_ip

  override fun getClientPort(): Int = client_port

  override fun getServerIP(): String? = server_ip

  override fun getServerPort(): Int = server_port

  fun getServerName(): String? = server_name

  override fun getUseSSL(): Boolean = use_ssl

  fun getClient(): InetSocketAddress = InetSocketAddress(client_ip, client_port)

  fun getServer(): InetSocketAddress = InetSocketAddress(server_ip, server_port)

  fun getContentType(): String? = content_type

  fun setContentType(content_type: String?) {
    this.content_type = content_type
  }

  override fun getEncoder(): String? = encoder_name

  override fun getAlpn(): String? = alpn

  fun getDate(): Date? = date

  override fun getConn(): Int = conn

  fun getGroup(): Long = group

  fun setGroup(group: Long) {
    this.group = group
  }

  fun getColor(): String? = color

  fun setColor(color: String) {
    this.color = color
  }

  fun getJobId(): String? = job_id

  fun setJobId(job_id: String?) {
    this.job_id = job_id
  }

  fun getTemporaryId(): String? = temporary_id

  fun setTemporaryId(temporary_id: String?) {
    this.temporary_id = temporary_id
  }

  fun getSummarizedRequestColumn(): String? = summarized_request

  fun getSummarizedResponseColumn(): String? = summarized_response

  fun getDisplayLength(): Int = display_length

  fun setSummarizedRequestColumn(value: String?) {
    summarized_request = value
  }

  fun setSummarizedResponseColumn(value: String?) {
    summarized_response = value
  }

  fun setDisplayLength(value: Int) {
    display_length = value
  }

  fun refreshPersistedSummaries(summarizer: PacketSummarizer) {
    val displayData =
      when {
        getModifiedData().isNotEmpty() -> getModifiedData()
        getDecodedData().isNotEmpty() -> getDecodedData()
        else -> getReceivedData()
      }
    display_length = displayData.size
    when (direction) {
      Direction.CLIENT -> {
        summarized_request = summarizer.summarizeRequest(encoder_name, alpn, this)
        summarized_response = ""
      }
      Direction.SERVER -> {
        summarized_request = ""
        summarized_response = summarizer.summarizeResponse(encoder_name, alpn, this)
      }
      null -> {
        summarized_request = ""
        summarized_response = ""
      }
    }
  }

  @Throws(Exception::class)
  fun getSummarizedRequest(summarizer: PacketSummarizer = NoOpPacketSummarizer()): String {
    if (getDirection() != Direction.CLIENT) return ""
    val persisted = summarized_request
    if (!persisted.isNullOrEmpty()) {
      return persisted
    }
    return summarizer.summarizeRequest(encoder_name, null, this)
  }

  @Throws(Exception::class)
  fun getSummarizedResponse(summarizer: PacketSummarizer = NoOpPacketSummarizer()): String {
    if (getDirection() != Direction.SERVER) return ""
    val persisted = summarized_response
    if (!persisted.isNullOrEmpty()) {
      return persisted
    }
    return summarizer.summarizeResponse(encoder_name, null, this)
  }

  fun decode() {}

  private fun initialize(
    listen_port: Int,
    client_ip: String,
    client_port: Int,
    server_ip: String,
    server_port: Int,
    server_name: String,
    use_ssl: Boolean,
    encoder: String,
    alpn: String,
    dir: Direction,
    conn: Int,
    group: Long,
  ) {
    this.listen_port = listen_port
    this.client_ip = client_ip
    this.client_port = client_port
    this.server_ip = server_ip
    this.server_port = server_port
    this.server_name = server_name
    content_type = ""
    this.use_ssl = use_ssl
    encoder_name = encoder
    this.alpn = alpn
    direction = dir
    received_data = byteArrayOf()
    decoded_data = byteArrayOf()
    modified_data = byteArrayOf()
    sent_data = byteArrayOf()
    modified = false
    resend = false
    date = Date()
    this.conn = conn
    this.group = group
    summarized_request = ""
    summarized_response = ""
    display_length = 0
    blob_flags = 0
  }

  companion object {
    const val FLAG_DECODED_ALIASES_RECEIVED = 1
    const val FLAG_MODIFIED_ALIASES_DECODED = 2
    const val FLAG_SENT_ALIASES_MODIFIED = 4
  }
}
