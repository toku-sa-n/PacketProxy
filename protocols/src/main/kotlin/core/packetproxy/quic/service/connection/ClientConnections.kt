package packetproxy.quic.service.connection

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.ArrayList
import java.util.LinkedHashMap
import java.util.Optional
import org.apache.commons.lang3.ArrayUtils
import packetproxy.CertCacheManager
import packetproxy.model.CAs.CA
import packetproxy.quic.service.packet.QuicPacketParser
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.util.errWithStackTrace

class ClientConnections(
  val listenPort: Int,
  private val ca: CA,
  private val certCacheManager: CertCacheManager,
) {
  private val connections = LinkedHashMap<ConnectionId, ClientConnection>()
  private val alreadyReceivedInitialSecrets = ArrayList<ConnectionId>()
  val socket: DatagramSocket =
    try {
      DatagramSocket(listenPort)
    } catch (e: Exception) {
      errWithStackTrace(e)
      throw e
    }

  fun close() {
    if (!socket.isClosed) {
      connections.values.forEach { it.close() }
      socket.close()
    }
  }

  @Throws(Exception::class)
  fun accept(): ClientConnection {
    while (true) {
      val udp = recvUdpPacket()
      val dest = QuicPacketParser.getDestConnectionId(udp.data)
      if (find(dest).isPresent) find(dest).get().recvUdpPacket(udp)
      else {
        val conn = create(dest, InetSocketAddress(udp.address, udp.port))
        if (conn.isPresent) {
          conn.get().recvUdpPacket(udp)
          return conn.get()
        }
      }
    }
  }

  fun find(dest: ConnectionId) = Optional.ofNullable(connections[dest])

  @Throws(Exception::class)
  fun create(initialSecret: ConnectionId, peer: InetSocketAddress): Optional<ClientConnection> {
    if (alreadyReceivedInitialSecrets.contains(initialSecret)) return Optional.empty()
    if (alreadyReceivedInitialSecrets.size >= MAX_INITIAL_SECRET_HISTORY) {
      alreadyReceivedInitialSecrets.removeAt(0)
    }
    alreadyReceivedInitialSecrets.add(initialSecret)
    val pair = ConnectionIdPair.generateRandom()
    val conn = ClientConnection(pair, initialSecret, socket, peer, ca, certCacheManager, listenPort)
    connections[pair.srcConnId] = conn
    pruneConnectionCache()
    return Optional.of(conn)
  }

  @Throws(Exception::class)
  private fun recvUdpPacket(): DatagramPacket {
    val buf = ByteArray(65535)
    val p = DatagramPacket(buf, 65535)
    socket.receive(p)
    p.data = ArrayUtils.subarray(p.data, 0, p.length)
    return p
  }

  private fun pruneConnectionCache() {
    while (connections.size > MAX_CONNECTION_CACHE) {
      val oldest = connections.entries.firstOrNull() ?: break
      oldest.value.close()
      connections.remove(oldest.key)
    }
  }

  companion object {
    private const val MAX_CONNECTION_CACHE = 4096
    private const val MAX_INITIAL_SECRET_HISTORY = 8192
  }
}
