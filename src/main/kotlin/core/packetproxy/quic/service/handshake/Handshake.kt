package packetproxy.quic.service.handshake

import net.luminis.tls.Message

interface Handshake {
  @Throws(Exception::class) fun received(message: Message)
}
