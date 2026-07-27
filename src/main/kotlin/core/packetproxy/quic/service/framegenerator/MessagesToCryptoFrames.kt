package packetproxy.quic.service.framegenerator

import net.luminis.tls.handshake.HandshakeMessage
import org.apache.commons.lang3.ArrayUtils
import packetproxy.quic.service.frame.Frames
import packetproxy.quic.service.frame.FramesBuilder
import packetproxy.quic.value.frame.CryptoFrame

class MessagesToCryptoFrames {
  private val handshakeMessages = mutableListOf<HandshakeMessage>()
  private var offset = 0L

  @Synchronized
  fun write(msg: HandshakeMessage) {
    handshakeMessages.add(msg)
  }

  @Synchronized
  fun toCryptoFrames(): Frames {
    val b = FramesBuilder()
    for (msg in handshakeMessages) {
      val bytes = msg.bytes
      var len = bytes.size
      var off = 0
      while (len > 0) {
        val sub = minOf(len, 1200)
        b.add(CryptoFrame(offset, ArrayUtils.subarray(bytes, off, off + sub)))
        offset += sub
        off += sub
        len -= sub
      }
    }
    handshakeMessages.clear()
    return b.build()
  }
}
