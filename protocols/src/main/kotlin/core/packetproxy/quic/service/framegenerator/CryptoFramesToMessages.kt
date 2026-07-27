package packetproxy.quic.service.framegenerator

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.util.ArrayList
import java.util.Optional
import net.luminis.tls.ProtectionKeysType
import net.luminis.tls.TlsProtocolException
import net.luminis.tls.handshake.*
import org.apache.commons.lang3.ArrayUtils
import packetproxy.quic.value.frame.CryptoFrame

class CryptoFramesToMessages {
  companion object {
    @Throws(Exception::class)
    @JvmStatic
    fun convertToHandshakeMessage(bytes: ByteArray) =
      TlsMessageParser()
        .parseAndProcessHandshakeMessage(
          ByteBuffer.wrap(bytes),
          DebugMessageProcessor(),
          ProtectionKeysType.None,
        )
  }

  private val cryptoFrames = ArrayList<CryptoFrame>()
  private val messages = ByteArrayOutputStream()
  private var nextMessageLength = 0
  private var alreadyParsedBytes = 0

  fun write(f: CryptoFrame) {
    cryptoFrames.add(f)
  }

  fun getHandshakeMessages(): List<HandshakeMessage> {
    val r = ArrayList<HandshakeMessage>()
    var o = getHandshakeMessage()
    while (o.isPresent) {
      r.add(o.get())
      o = getHandshakeMessage()
    }
    return r
  }

  fun getHandshakeMessage(): Optional<HandshakeMessage> {
    if (nextMessageLength == 0) {
      if (messages.size() < 4 && !refill(alreadyParsedBytes + messages.size().toLong()))
        return Optional.empty()
      val data = messages.toByteArray()
      if (data.size < 4) return Optional.empty()
      nextMessageLength =
        4 +
          (((data[1].toInt() and 0xff) shl 16) or
            ((data[2].toInt() and 0xff) shl 8) or
            (data[3].toInt() and 0xff))
    }
    while (messages.size() < nextMessageLength) if (
      !refill(alreadyParsedBytes + messages.size().toLong())
    )
      return Optional.empty()
    val all = messages.toByteArray()
    val msg = ArrayUtils.subarray(all, 0, nextMessageLength)
    val rem = ArrayUtils.subarray(all, nextMessageLength, all.size)
    messages.reset()
    messages.write(rem)
    nextMessageLength = 0
    alreadyParsedBytes += msg.size
    return Optional.of(
      TlsMessageParser()
        .parseAndProcessHandshakeMessage(
          ByteBuffer.wrap(msg),
          DebugMessageProcessor(),
          ProtectionKeysType.None,
        )
    )
  }

  private fun refill(offset: Long) =
    cryptoFrames
      .firstOrNull { it.offset == offset }
      ?.let {
        messages.write(it.data)
        true
      } ?: false

  private class DebugMessageProcessor : MessageProcessor {
    @Throws(TlsProtocolException::class, IOException::class)
    override fun received(ch: ClientHello, p: ProtectionKeysType) {}

    @Throws(TlsProtocolException::class, IOException::class)
    override fun received(sh: ServerHello, p: ProtectionKeysType) {}

    @Throws(TlsProtocolException::class, IOException::class)
    override fun received(ee: EncryptedExtensions, p: ProtectionKeysType) {}

    @Throws(TlsProtocolException::class, IOException::class)
    override fun received(cm: CertificateMessage, p: ProtectionKeysType) {}

    @Throws(TlsProtocolException::class, IOException::class)
    override fun received(cv: CertificateVerifyMessage, p: ProtectionKeysType) {}

    @Throws(TlsProtocolException::class, IOException::class)
    override fun received(fm: FinishedMessage, p: ProtectionKeysType) {}

    @Throws(TlsProtocolException::class, IOException::class)
    override fun received(nst: NewSessionTicketMessage, p: ProtectionKeysType) {}

    @Throws(TlsProtocolException::class, IOException::class)
    override fun received(cr: CertificateRequestMessage, p: ProtectionKeysType) {}
  }
}
