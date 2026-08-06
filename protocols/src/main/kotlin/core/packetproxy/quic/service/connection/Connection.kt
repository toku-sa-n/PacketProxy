package packetproxy.quic.service.connection

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.InterruptedIOException
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import packetproxy.common.Endpoint
import packetproxy.common.PipeEndpoint
import packetproxy.quic.service.LossDetection
import packetproxy.quic.service.Pto
import packetproxy.quic.service.RttEstimator
import packetproxy.quic.service.connection.helper.AwaitingPackets
import packetproxy.quic.service.handshake.Handshake
import packetproxy.quic.service.handshake.HandshakeState
import packetproxy.quic.service.key.Keys
import packetproxy.quic.service.packet.QuicPacketParser
import packetproxy.quic.service.pnspace.PnSpaces
import packetproxy.quic.utils.Constants
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.quic.value.QuicMessages
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.packet.longheader.pnspace.HandshakePacket
import packetproxy.quic.value.packet.longheader.pnspace.InitialPacket
import packetproxy.quic.value.packet.shortheader.ShortHeaderPacket
import packetproxy.util.errWithStackTrace
import packetproxy.util.rethrow

abstract class Connection(
  val role: Constants.Role,
  var connIdPair: ConnectionIdPair,
  val initialSecret: ConnectionId,
  val socket: DatagramSocket,
  val peerAddr: InetSocketAddress,
) : Endpoint {
  abstract val handshake: Handshake
  val executor = Executors.newFixedThreadPool(3)
  val clientPacketParser: QuicPacketParser
  val serverPacketParser: QuicPacketParser
  val awaitingSendPackets = AwaitingPackets<packetproxy.quic.value.packet.QuicPacket>()
  val awaitingReceivedPackets = AwaitingPackets<DatagramPacket>()
  val handshakeState = HandshakeState()
  val keys = Keys()
  val pto: Pto
  val lossDetection: LossDetection
  val rttEstimator: RttEstimator
  val pnSpaces: PnSpaces
  val pipe: PipeEndpoint
  var serverAntiAmplifiedLimit = false

  init {
    clientPacketParser = QuicPacketParser(this, keys.clientKeys)
    serverPacketParser = QuicPacketParser(this, keys.serverKeys)
    pto = Pto(this)
    lossDetection = LossDetection(this)
    rttEstimator = RttEstimator(this)
    pnSpaces = PnSpaces(this)
    pipe = PipeEndpoint(peerAddr)
    keys.computeInitialKey(initialSecret)
  }

  @Throws(Exception::class)
  protected fun start() {
    executor.submit {
      while (true) {
        awaitingSendPackets.put(pnSpaces.pollSendPackets())
        awaitingSendPackets.forEachAndRemovedIfReturnTrue { packet ->
          try {
            when (packet) {
              is InitialPacket ->
                if (keys.discardedInitialKey()) true
                else {
                  sendUdpPacket(
                    if (role == Constants.Role.CLIENT)
                      packet.getBytes(
                        keys.clientKeys.initialKey,
                        getPnSpace(packet.pnSpaceType).ackFrameGenerator.getSmallestValidPn(),
                      )
                    else
                      packet.getBytes(
                        keys.serverKeys.initialKey,
                        getPnSpace(packet.pnSpaceType).ackFrameGenerator.getSmallestValidPn(),
                      )
                  )
                  true
                }
              is HandshakePacket ->
                if (keys.discardedHandshakeKey()) true
                else {
                  sendUdpPacket(
                    if (role == Constants.Role.CLIENT)
                      packet.getBytes(
                        keys.clientKeys.handshakeKey,
                        getPnSpace(packet.pnSpaceType).ackFrameGenerator.getSmallestValidPn(),
                      )
                    else
                      packet.getBytes(
                        keys.serverKeys.handshakeKey,
                        getPnSpace(packet.pnSpaceType).ackFrameGenerator.getSmallestValidPn(),
                      )
                  )
                  true
                }
              is ShortHeaderPacket ->
                if (
                  !keys.hasApplicationKey() ||
                    (role == Constants.Role.CLIENT && handshakeState.isNotConfirmed())
                )
                  false
                else {
                  sendUdpPacket(
                    if (role == Constants.Role.CLIENT)
                      packet.getBytes(
                        keys.clientKeys.applicationKey,
                        getPnSpace(packet.pnSpaceType).ackFrameGenerator.getSmallestValidPn(),
                      )
                    else
                      packet.getBytes(
                        keys.serverKeys.applicationKey,
                        getPnSpace(packet.pnSpaceType).ackFrameGenerator.getSmallestValidPn(),
                      )
                  )
                  true
                }
              else -> false
            }
          } catch (e: Exception) {
            errWithStackTrace(e)
            false
          }
        }
      }
    }
    executor.submit {
      try {
        val input = pipe.getRawEndpoint().getInputStream()
        if (role == Constants.Role.CLIENT) while (!handshakeState.isConfirmed()) Thread.sleep(100)
        val chunk = ByteArray(4096)
        val q = ByteArrayOutputStream()
        var n: Int
        while (input.read(chunk).also { n = it } > 0) {
          q.write(chunk, 0, n)
          val b = ByteBuffer.wrap(q.toByteArray())
          QuicMessages.parse(b)
            .forEach(
              rethrow {
                getPnSpace(Constants.PnSpaceType.PnSpaceApplicationData).addSendQuicMessage(it)
              }
            )
          q.reset()
          if (b.hasRemaining()) q.write(SimpleBytes.parse(b, b.remaining().toLong()).bytes)
        }
      } catch (_: InterruptedIOException) {} catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  @Throws(Exception::class)
  private fun sendUdpPacket(data: ByteArray) {
    socket.send(DatagramPacket(data, 0, data.size, peerAddr))
  }

  fun updateDestConnId(id: ConnectionId) {
    connIdPair = ConnectionIdPair.of(connIdPair.srcConnId, id)
  }

  fun getPnSpace(t: PnSpaceType) = pnSpaces.getPnSpace(t)

  fun close() {
    try {
      pipe.getRawEndpoint().getInputStream().close()
      pipe.getRawEndpoint().getOutputStream().close()
      executor.shutdownNow()
      executor.awaitTermination(2, java.util.concurrent.TimeUnit.SECONDS)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  override fun getInputStream(): InputStream = pipe.getProxyRawEndpoint().getInputStream()

  @Throws(Exception::class)
  override fun getOutputStream(): OutputStream = pipe.getProxyRawEndpoint().getOutputStream()

  override fun getAddress() = peerAddr

  override fun getLocalPort() = 0

  override fun getName() = "QUIC Endpoint"

  fun peerAwaitingAddressValidation() = !peerCompletedAddressValidation()

  abstract fun peerCompletedAddressValidation(): Boolean
}
