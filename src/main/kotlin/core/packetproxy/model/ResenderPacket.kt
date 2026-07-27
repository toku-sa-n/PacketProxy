package packetproxy.model

import com.j256.ormlite.field.DataType
import com.j256.ormlite.field.DatabaseField
import com.j256.ormlite.table.DatabaseTable
import java.net.InetSocketAddress

@DatabaseTable(tableName = "resender_packets")
class ResenderPacket {
  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField(uniqueCombo = true) private var resendsIndex = 0

  @field:DatabaseField(uniqueCombo = true) private var resendIndex = 0

  @field:DatabaseField(dataType = DataType.ENUM_STRING, uniqueCombo = true)
  private var direction: Packet.Direction? = null

  @field:DatabaseField(dataType = DataType.BYTE_ARRAY) private var data: ByteArray? = null

  @field:DatabaseField private var listenPort = 0

  @field:DatabaseField private var clientIp: String? = null

  @field:DatabaseField private var clientPort = 0

  @field:DatabaseField private var serverIp: String? = null

  @field:DatabaseField private var serverPort = 0

  @field:DatabaseField private var serverName: String? = null

  @field:DatabaseField private var useSsl = false

  @field:DatabaseField private var encoderName: String? = null

  @field:DatabaseField private var alpn: String? = null

  @field:DatabaseField private var autoModified = false

  @field:DatabaseField private var conn = 0

  @field:DatabaseField private var group = 0L

  constructor()

  constructor(
    resendsIndex: Int,
    resendIndex: Int,
    direction: Packet.Direction,
    data: ByteArray,
    listenPort: Int,
    clientIp: String,
    clientPort: Int,
    serverIp: String,
    serverPort: Int,
    serverName: String,
    useSsl: Boolean,
    encoderName: String,
    alpn: String,
    autoModified: Boolean,
    conn: Int,
    group: Long,
  ) {
    this.resendsIndex = resendsIndex
    this.resendIndex = resendIndex
    this.direction = direction
    this.data = data
    this.listenPort = listenPort
    this.clientIp = clientIp
    this.clientPort = clientPort
    this.serverIp = serverIp
    this.serverPort = serverPort
    this.serverName = serverName
    this.useSsl = useSsl
    this.encoderName = encoderName
    this.alpn = alpn
    this.autoModified = autoModified
    this.conn = conn
    this.group = group
  }

  fun getResendsIndex(): Int = resendsIndex

  fun getResendIndex(): Int = resendIndex

  fun getDirection(): Packet.Direction? = direction

  fun getOneShotPacket(): OneShotPacket =
    OneShotPacket(
      -1,
      listenPort,
      InetSocketAddress(clientIp, clientPort),
      InetSocketAddress(serverIp, serverPort),
      serverName!!,
      useSsl,
      data!!,
      encoderName!!,
      alpn!!,
      direction!!,
      conn,
      group,
    )
}
