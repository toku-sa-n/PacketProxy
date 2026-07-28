package packetproxy.quic.service.connection

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import org.apache.commons.lang3.ArrayUtils
import packetproxy.PrivateDNSClient
import packetproxy.model.Resolutions
import packetproxy.quic.service.handshake.ClientHandshake
import packetproxy.quic.utils.AwaitingException
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.util.errWithStackTrace

class ServerConnection(
  connIdPair: ConnectionIdPair,
  val serverName: String,
  serverPort: Int,
  resolutions: Resolutions,
) :
  Connection(
    Constants.Role.CLIENT,
    connIdPair,
    connIdPair.destConnId,
    DatagramSocket(),
    InetSocketAddress(PrivateDNSClient().getByName(serverName, resolutions), serverPort),
  ) {
  override val handshake = ClientHandshake(this)

  init {
    handshake.start(serverName)
    executor.submit(RecvUdpPacketsLoop())
    start()
  }

  inner class RecvUdpPacketsLoop : Runnable {
    override fun run() {
      while (true) {
        val p = recvUdpPacket()
        awaitingReceivedPackets.put(p)
        awaitingReceivedPackets.forEachAndRemovedIfReturnTrue {
          try {
            serverPacketParser.parseOnePacket(it)
            true
          } catch (_: AwaitingException) {
            false
          } catch (e: Exception) {
            errWithStackTrace(e)
            false
          }
        }
      }
    }
  }

  @Throws(Exception::class)
  private fun recvUdpPacket(): DatagramPacket {
    val b = ByteArray(4096)
    val p = DatagramPacket(b, 4096)
    socket.receive(p)
    p.data = ArrayUtils.subarray(p.data, 0, p.length)
    return p
  }

  override fun peerCompletedAddressValidation() = handshakeState.isAckReceived()

  override fun getName() = serverName
}
