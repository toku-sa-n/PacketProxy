package packetproxy.quic.service.connection

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.ArrayList
import java.util.HashMap
import java.util.Optional
import java.util.concurrent.Executors
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
  private val connes = HashMap<ConnectionId, ClientConnection>()
  private val alreadyReceivedInitialSecrets = ArrayList<ConnectionId>()
  private val executor = Executors.newFixedThreadPool(2)
  val socket: DatagramSocket =
    try {
      DatagramSocket(listenPort)
    } catch (e: Exception) {
      errWithStackTrace(e)
      throw e
    }

  fun close() {
    if (!socket.isClosed) {
      connes.values.forEach { it.close() }
      executor.shutdownNow()
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

  fun find(dest: ConnectionId) = Optional.ofNullable(connes[dest])

  @Throws(Exception::class)
  fun create(initialSecret: ConnectionId, peer: InetSocketAddress): Optional<ClientConnection> {
    if (alreadyReceivedInitialSecrets.contains(initialSecret)) return Optional.empty()
    alreadyReceivedInitialSecrets.add(initialSecret)
    val pair = ConnectionIdPair.generateRandom()
    val conn = ClientConnection(pair, initialSecret, socket, peer, ca, certCacheManager, listenPort)
    connes[pair.srcConnId] = conn
    return Optional.of(conn)
  }

  @Throws(Exception::class)
  private fun recvUdpPacket(): DatagramPacket {
    val buf = ByteArray(4096)
    val p = DatagramPacket(buf, 4096)
    socket.receive(p)
    p.data = ArrayUtils.subarray(p.data, 0, p.length)
    return p
  }
}
