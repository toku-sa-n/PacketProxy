package packetproxy.quic.service.handshake

import java.io.IOException
import java.security.interfaces.RSAPrivateKey
import java.util.Optional
import java.util.concurrent.LinkedBlockingQueue
import net.luminis.tls.*
import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension
import net.luminis.tls.extension.Extension
import net.luminis.tls.extension.ServerNameExtension
import net.luminis.tls.handshake.*
import packetproxy.CertCacheManager
import packetproxy.model.CAs.CA
import packetproxy.quic.service.connection.Connection
import packetproxy.quic.service.frame.Frames
import packetproxy.quic.service.transportparameter.TransportParameters
import packetproxy.quic.utils.Constants
import packetproxy.quic.utils.Constants.PnSpaceType.*
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.Token
import packetproxy.quic.value.frame.NewConnectionIdFrame
import packetproxy.util.Logging.err
import packetproxy.util.Throwing.rethrow

class ServerHandshake(val conn: Connection, private val ca: CA) : Handshake {
  private val sniQueue = LinkedBlockingQueue<String>()
  val clientTransportParams = TransportParameters(Constants.Role.CLIENT)
  private var sniName: Optional<String> = Optional.empty()
  private lateinit var engine: TlsServerEngine

  @Throws(Exception::class)
  fun startHandshake(sni: String) {
    val ks = CertCacheManager.getInstance().getKeyStore(sni, arrayOf(sni), ca)
    val key = ks.getKey("newalias", "testtest".toCharArray()) as RSAPrivateKey
    val certs = ks.getCertificateChain("newalias").map { it as java.security.cert.X509Certificate }
    engine =
      TlsServerEngine(
        certs,
        key,
        MyServerMessageSender(),
        MyTlsStatusEventHandler(),
        tlsSessionRegistry,
      )
    engine.addSupportedCiphers(listOf(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256))
  }

  @Throws(Exception::class)
  override fun received(message: Message) =
    when (message) {
      is ClientHello -> {
        message.extensions
          .stream()
          .filter { it is ServerNameExtension }
          .findFirst()
          .ifPresent(rethrow { sniName = Optional.of((it as ServerNameExtension).hostName) })
        if (sniName.isEmpty)
          throw Exception("Error: SNI name was not found in TLS ClientHello HandShake message")
        sniName.ifPresent(
          rethrow { sni ->
            startHandshake(sni)
            sniQueue.put(sni)
            engine.received(message, ProtectionKeysType.None)
          }
        )
      }
      is EncryptedExtensions -> {}
      is FinishedMessage -> engine.received(message, ProtectionKeysType.Handshake)
      else -> err("Error: cannot process message %s", message)
    }

  @Throws(Exception::class) fun getSNI() = sniQueue.take()

  private inner class MyServerMessageSender : ServerMessageSender {
    private fun send(space: Constants.PnSpaceType, msg: HandshakeMessage) {
      val s = conn.getPnSpace(space).msgToFrameCryptoStream
      s.write(msg)
      conn.getPnSpace(space).addSendFrames(s.toCryptoFrames())
    }

    @Throws(IOException::class)
    override fun send(sh: ServerHello) {
      send(PnSpaceInitial, sh)
      conn.keys.clientRandom = sh.random
    }

    @Throws(IOException::class)
    override fun send(ee: EncryptedExtensions) {
      send(PnSpaceHandshake, ee)
    }

    @Throws(IOException::class)
    override fun send(cm: CertificateMessage) {
      send(PnSpaceHandshake, cm)
    }

    @Throws(IOException::class)
    override fun send(cv: CertificateVerifyMessage) {
      send(PnSpaceHandshake, cv)
    }

    @Throws(IOException::class)
    override fun send(fm: FinishedMessage) {
      send(PnSpaceHandshake, fm)
    }

    @Throws(IOException::class)
    override fun send(t: NewSessionTicketMessage) {
      send(PnSpaceApplicationData, t)
      conn
        .getPnSpace(PnSpaceApplicationData)
        .addSendFrames(
          Frames.of(
            NewConnectionIdFrame(
              1,
              0,
              ConnectionId.generateRandom(),
              Token.generateRandom(Constants.TOKEN_SIZE),
            )
          )
        )
    }
  }

  private inner class MyTlsStatusEventHandler : TlsStatusEventHandler {
    override fun earlySecretsKnown() {
      conn.keys.computeZeroRttKey(engine.clientEarlyTrafficSecret)
    }

    override fun handshakeSecretsKnown() {
      conn.keys.computeHandshakeKey(
        engine.clientHandshakeTrafficSecret,
        engine.serverHandshakeTrafficSecret,
      )
    }

    override fun handshakeFinished() {
      conn.keys.computeApplicationKey(
        engine.clientApplicationTrafficSecret,
        engine.serverApplicationTrafficSecret,
      )
      conn.keys.discardInitialKey()
      conn.getPnSpace(PnSpaceInitial).close()
      conn.keys.discardHandshakeKey()
      conn.getPnSpace(PnSpaceHandshake).close()
    }

    override fun newSessionTicketReceived(t: NewSessionTicket) {}

    @Throws(TlsProtocolException::class)
    override fun extensionsReceived(e: List<Extension>) {
      engine.addServerExtensions(ApplicationLayerProtocolNegotiationExtension("h3"))
      val tp = TransportParameters(Constants.Role.SERVER)
      tp.maxUdpPayloadSize = 1472
      tp.ackDelayExponent = 10
      tp.maxIdleTimeout = 30_000
      tp.oldMinAckDelay = 25000
      tp.origDestConnId = conn.initialSecret.bytes
      tp.initSrcConnId = conn.connIdPair.srcConnId.bytes
      tp.initMaxStreamUni = 10 * 1024
      tp.initMaxStreamBidi = 10 * 1024
      tp.initMaxData = 10L * 1024 * 1024 * 1024
      tp.initMaxStreamDataBidiLocal = 10L * 1024 * 1024 * 1024
      tp.initMaxStreamDataBidiRemote = 10L * 1024 * 1024 * 1024
      tp.initMaxStreamDataUni = 10L * 1024 * 1024 * 1024
      tp.activeConnIdLimit = 2
      tp.disableActiveMigration = true
      engine.addServerExtensions(tp)
    }

    override fun isEarlyDataAccepted() = false
  }

  companion object {
    private val tlsSessionRegistry: TlsSessionRegistry = TlsSessionRegistryImpl()
  }
}
