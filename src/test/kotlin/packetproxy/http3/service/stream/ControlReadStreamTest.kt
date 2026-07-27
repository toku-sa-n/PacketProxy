package packetproxy.http3.service.stream

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId

class ControlReadStreamTest {
  @Test
  @Throws(Exception::class)
  fun `連続したFrameの順番が保たれること`() {
    val stream = ControlReadStream(StreamId.of(0x2L))
    stream.write(QuicMessage.of(StreamId.of(0x2L), byteArrayOf(0x00, 0x04, 0x0)))
    assertThat(stream.readAllBytes()).isEqualTo(Hex.decodeHex("0400"))
  }
}
