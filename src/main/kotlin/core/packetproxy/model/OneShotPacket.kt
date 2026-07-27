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

import java.net.InetSocketAddress
import org.apache.commons.lang3.ArrayUtils
import packetproxy.EncoderManager
import packetproxy.common.Range
import packetproxy.common.Utils
import packetproxy.model.Packet.Direction
import packetproxy.util.Logging.err

class OneShotPacket : PacketInfo, Cloneable {
  private var id = 0
  private var direction: Packet.Direction? = null
  private var data: ByteArray? = null
  private var listenPort = 0
  private var clientIp: String? = null
  private var clientPort = 0
  private var serverIp: String? = null
  private var serverPort = 0
  private var serverName: String? = null
  private var useSsl = false
  private var encoderName: String? = null
  private var alpn: String? = null
  private var autoModified = false
  private var conn = 0
  private var group = 0L
  private var jobId: String? = null
  private var temporaryId: String? = null

  constructor()

  constructor(
    id: Int,
    listenPort: Int,
    clientAddr: InetSocketAddress,
    serverAddr: InetSocketAddress,
    serverName: String,
    useSsl: Boolean,
    data: ByteArray,
    encoderName: String,
    alpn: String,
    direction: Packet.Direction,
    conn: Int,
    group: Long,
  ) : this(
    id,
    listenPort,
    clientAddr,
    serverAddr,
    serverName,
    useSsl,
    data,
    encoderName,
    alpn,
    direction,
    conn,
    group,
    null,
    null,
  )

  constructor(
    id: Int,
    listenPort: Int,
    clientAddr: InetSocketAddress,
    serverAddr: InetSocketAddress,
    serverName: String,
    useSsl: Boolean,
    data: ByteArray,
    encoderName: String,
    alpn: String,
    direction: Packet.Direction,
    conn: Int,
    group: Long,
    jobId: String?,
    temporaryId: String?,
  ) {
    initialize(
      id,
      listenPort,
      clientAddr.address.hostAddress,
      clientAddr.port,
      serverAddr.address.hostAddress,
      serverAddr.port,
      serverName,
      useSsl,
      data,
      encoderName,
      alpn,
      direction,
      conn,
      group,
      jobId,
      temporaryId,
    )
  }

  public override fun clone(): Any = super.clone()

  override fun getDirection(): Packet.Direction? = direction

  fun setId(id: Int) {
    this.id = id
  }

  override fun getId(): Int = id

  fun setData(data: ByteArray) {
    this.data = data
  }

  fun replaceData(area: Range, replacer: ByteArray) {
    data = Utils.replaceArray(data ?: byteArrayOf(), area, replacer)
  }

  fun getData(area: Range): ByteArray =
    ArrayUtils.subarray(data, area.positionStart, area.positionEnd)

  fun getData(): ByteArray = data ?: byteArrayOf()

  fun setAutoModified() {
    autoModified = true
  }

  fun getAutoModified(): Boolean = autoModified

  override fun getListenPort(): Int = listenPort

  override fun getClientIP(): String? = clientIp

  override fun getClientPort(): Int = clientPort

  override fun getServerIP(): String? = serverIp

  override fun getServerPort(): Int = serverPort

  fun getServerName(): String? = serverName

  override fun getUseSSL(): Boolean = useSsl

  fun getClient(): InetSocketAddress = InetSocketAddress(clientIp, clientPort)

  fun getServer(): InetSocketAddress = InetSocketAddress(serverIp, serverPort)

  override fun getEncoder(): String? = encoderName

  fun setEncoder(encoderName: String) {
    this.encoderName = encoderName
  }

  override fun getAlpn(): String? = alpn

  fun setAlpn(alpn: String) {
    this.alpn = alpn
  }

  override fun getConn(): Int = conn

  fun getGroup(): Long = group

  fun getJobId(): String? = jobId

  fun setJobId(jobId: String?) {
    this.jobId = jobId
  }

  fun getTemporaryId(): String? = temporaryId

  fun setTemporaryId(temporaryId: String?) {
    this.temporaryId = temporaryId
  }

  fun encode() {}

  fun toPacket(): Packet {
    val packet =
      Packet(
        listenPort,
        clientIp!!,
        clientPort,
        serverIp!!,
        serverPort,
        serverName!!,
        useSsl,
        encoderName!!,
        alpn!!,
        direction!!,
        conn,
        group,
      )
    packet.setDecodedData(getData())
    packet.setJobId(jobId)
    packet.setTemporaryId(temporaryId)
    return packet
  }

  fun getSummarizedRequest(): String {
    var encoder = EncoderManager.getInstance().createInstance(encoderName ?: "", alpn)
    if (encoder == null) {
      err("エンコードモジュール: %s が見当たらないので、Sample とみなしました", encoderName)
      encoder = EncoderManager.getInstance().createInstance("Sample", alpn)
    }
    return if (direction == Direction.CLIENT) encoder.getSummarizedRequest(toPacket()) else ""
  }

  fun getSummarizedResponse(): String {
    var encoder = EncoderManager.getInstance().createInstance(encoderName ?: "", alpn)
    if (encoder == null) {
      err("エンコードモジュール: %s が見当たらないので、Sample とみなしました", encoderName)
      encoder = EncoderManager.getInstance().createInstance("Sample", alpn)
    }
    return if (direction == Direction.SERVER) encoder.getSummarizedResponse(toPacket()) else ""
  }

  fun getResenderPacket(resendsIndex: Int, resendIndex: Int): ResenderPacket =
    ResenderPacket(
      resendsIndex,
      resendIndex,
      direction!!,
      data!!,
      listenPort,
      clientIp!!,
      clientPort,
      serverIp!!,
      serverPort,
      serverName!!,
      useSsl,
      encoderName!!,
      alpn!!,
      autoModified,
      conn,
      group,
    )

  private fun initialize(
    id: Int,
    listenPort: Int,
    clientIp: String,
    clientPort: Int,
    serverIp: String,
    serverPort: Int,
    serverName: String,
    useSsl: Boolean,
    data: ByteArray,
    encoderName: String,
    alpn: String,
    direction: Packet.Direction,
    conn: Int,
    group: Long,
    jobId: String?,
    temporaryId: String?,
  ) {
    this.id = id
    this.listenPort = listenPort
    this.clientIp = clientIp
    this.clientPort = clientPort
    this.serverIp = serverIp
    this.serverPort = serverPort
    this.serverName = serverName
    this.useSsl = useSsl
    this.data = data
    this.encoderName = encoderName
    this.alpn = alpn
    this.direction = direction
    autoModified = false
    this.conn = conn
    this.group = group
    this.jobId = jobId
    this.temporaryId = temporaryId
  }
}
