package packetproxy.http3.service.stream

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId

class QpackReadStreamTest {
  @Test
  @Throws(Exception::class)
  fun `writeしたものがreadできること`() {
    val stream = QpackReadStream(StreamId.of(0xaL), Stream.StreamType.QpackEncoderStreamType)
    stream.write(QuicMessage.of(StreamId.of(0xaL), Hex.decodeHex("02112233")))
    assertThat(stream.readAllBytes()).isEqualTo(Hex.decodeHex("112233"))
  }

  @Test
  fun `streamTypeが異なるものがwriteされたら例外が起きること`() {
    val stream = QpackReadStream(StreamId.of(0xaL), Stream.StreamType.QpackEncoderStreamType)
    assertThatThrownBy {
        stream.write(QuicMessage.of(StreamId.of(0xaL), Hex.decodeHex("03112233")))
      }
      .isInstanceOf(Exception::class.java)
  }
}
