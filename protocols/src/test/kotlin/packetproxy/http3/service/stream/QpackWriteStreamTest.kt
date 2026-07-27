package packetproxy.http3.service.stream

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId

class QpackWriteStreamTest {
  @Test
  @Throws(Exception::class)
  fun `writeしたものがreadできること`() {
    val stream = QpackWriteStream(StreamId.of(0xaL), Stream.StreamType.QpackDecoderStreamType)
    stream.write(byteArrayOf(0x11, 0x22, 0x33))
    val messages = stream.readAllQuicMessages()
    assertThat(messages.size()).isEqualTo(1)
    assertThat(messages[0])
      .isEqualTo(QuicMessage.of(StreamId.of(0xaL), byteArrayOf(0x3, 0x11, 0x22, 0x33)))
  }
}
