package packetproxy.quic.service.connection

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import javax.crypto.AEADBadTagException
import packetproxy.CertCacheManager
import packetproxy.common.Endpoint
import packetproxy.model.CAs.CA
import packetproxy.quic.service.handshake.ServerHandshake
import packetproxy.quic.utils.AwaitingException
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.util.errWithStackTrace

class ClientConnection(
  connIdPair: ConnectionIdPair,
  initialSecret: ConnectionId,
  socket: DatagramSocket,
  peerAddr: InetSocketAddress,
  ca: CA,
  certCacheManager: CertCacheManager,
  val listenPortNum: Int,
) : Connection(Constants.Role.SERVER, connIdPair, initialSecret, socket, peerAddr), Endpoint {
  override val handshake = ServerHandshake(this, ca, certCacheManager)

  init {
    start()
  }

  @Throws(Exception::class) fun getSNI() = handshake.getSNI()

  fun recvUdpPacket(udpPacket: DatagramPacket) {
    awaitingReceivedPackets.put(udpPacket)
    awaitingReceivedPackets.forEachAndRemovedIfReturnTrue {
      try {
        clientPacketParser.parseOnePacket(it)
        true
      } catch (_: AwaitingException) {
        false
      } catch (_: java.io.IOException) {
        true
      } catch (e: AEADBadTagException) {
        errWithStackTrace(e)
        true
      } catch (e: Exception) {
        errWithStackTrace(e)
        true
      }
    }
  }

  override fun peerCompletedAddressValidation() = true

  override fun getLocalPort() = listenPortNum

  override fun getName() = "QUIC Client Endpoint"
}
