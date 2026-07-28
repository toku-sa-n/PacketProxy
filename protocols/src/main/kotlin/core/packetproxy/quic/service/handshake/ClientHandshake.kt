package packetproxy.quic.service.handshake

import java.io.IOException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager
import net.luminis.tls.*
import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension
import net.luminis.tls.extension.Extension
import net.luminis.tls.handshake.*
import packetproxy.quic.service.connection.Connection
import packetproxy.quic.service.handshake.HandshakeState.State.*
import packetproxy.quic.service.transportparameter.TransportParameters
import packetproxy.quic.utils.Constants
import packetproxy.quic.utils.Constants.PnSpaceType.*
import packetproxy.util.err

class ClientHandshake(private val conn: Connection) : Handshake {
  private val engine: TlsClientEngine

  init {
    engine = TlsClientEngine(MyClientMessageSender(), MyClientTlsStatusEventHandler())
    engine.addSupportedCiphers(listOf(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256))
    engine.add(ApplicationLayerProtocolNegotiationExtension("h3"))
    engine.setTrustManager(
      object : X509TrustManager {
        @Throws(CertificateException::class)
        override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}

        @Throws(CertificateException::class)
        override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}

        override fun getAcceptedIssuers() = emptyArray<X509Certificate>()
      }
    )
    engine.setHostnameVerifier(HostnameVerifier { _, _ -> true })
    val tp = TransportParameters(Constants.Role.CLIENT)
    tp.initSrcConnId = conn.connIdPair.srcConnId.bytes
    tp.maxUdpPayloadSize = 1472
    tp.ackDelayExponent = 10
    tp.maxIdleTimeout = 30_000
    tp.oldMinAckDelay = 25_000
    tp.initMaxStreamUni = 10 * 1024
    tp.initMaxStreamBidi = 10 * 1024
    tp.initMaxData = 10L * 1024 * 1024 * 1024
    tp.initMaxStreamDataBidiLocal = 10L * 1024 * 1024 * 1024
    tp.initMaxStreamDataBidiRemote = 10L * 1024 * 1024 * 1024
    tp.initMaxStreamDataUni = 10L * 1024 * 1024 * 1024
    tp.activeConnIdLimit = 4
    engine.add(tp)
  }

  @Throws(Exception::class)
  override fun received(message: Message) =
    when (message) {
      is ServerHello -> engine.received(message, ProtectionKeysType.None)
      is EncryptedExtensions -> engine.received(message, ProtectionKeysType.Handshake)
      is CertificateMessage -> engine.received(message, ProtectionKeysType.Handshake)
      is CertificateVerifyMessage -> engine.received(message, ProtectionKeysType.Handshake)
      is FinishedMessage -> engine.received(message, ProtectionKeysType.Handshake)
      is NewSessionTicketMessage -> engine.received(message, ProtectionKeysType.Application)
      else -> err("Error: couldn't process message %s", message)
    }

  @Throws(Exception::class)
  fun start(serverName: String) {
    engine.setServerName(serverName)
    engine.startHandshake()
  }

  private inner class MyClientMessageSender : ClientMessageSender {
    @Throws(IOException::class)
    override fun send(ch: ClientHello) {
      val s = conn.getPnSpace(PnSpaceInitial).msgToFrameCryptoStream
      s.write(ch)
      conn.getPnSpace(PnSpaceInitial).addSendFrames(s.toCryptoFrames())
      conn.keys.clientRandom = ch.clientRandom
    }

    @Throws(IOException::class)
    override fun send(fm: FinishedMessage) {
      val s = conn.getPnSpace(PnSpaceHandshake).msgToFrameCryptoStream
      s.write(fm)
      conn.getPnSpace(PnSpaceHandshake).addSendFrames(s.toCryptoFrames())
      conn.handshakeState.transit(Confirmed)
    }

    @Throws(IOException::class) override fun send(cm: CertificateMessage) {}

    override fun send(cv: CertificateVerifyMessage) {}
  }

  private inner class MyClientTlsStatusEventHandler : TlsStatusEventHandler {
    override fun earlySecretsKnown() {
      conn.keys.computeZeroRttKey(engine.clientEarlyTrafficSecret)
    }

    override fun handshakeSecretsKnown() {
      conn.keys.computeHandshakeKey(
        engine.clientHandshakeTrafficSecret,
        engine.serverHandshakeTrafficSecret,
      )
      conn.handshakeState.transit(HasHandshakeKeys)
    }

    override fun handshakeFinished() {
      conn.keys.computeApplicationKey(
        engine.clientApplicationTrafficSecret,
        engine.serverApplicationTrafficSecret,
      )
      conn.handshakeState.transit(HasAppKeys)
    }

    override fun newSessionTicketReceived(t: NewSessionTicket) {}

    @Throws(TlsProtocolException::class) override fun extensionsReceived(e: List<Extension>) {}

    override fun isEarlyDataAccepted() = false
  }
}
