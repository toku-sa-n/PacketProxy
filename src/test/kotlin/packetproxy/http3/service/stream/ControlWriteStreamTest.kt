package packetproxy.http3.service.stream

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import packetproxy.http3.value.Setting
import packetproxy.quic.value.StreamId

class ControlWriteStreamTest {
  @Test
  @Throws(Exception::class)
  fun `最初のreadQuicMessagesでSreamIdが出力されること`() {
    val stream = ControlWriteStream(StreamId.of(0x2L))
    stream.write(byteArrayOf(0x04, 0x00))
    assertThat(stream.readAllQuicMessages()[0].data)
      .isEqualTo(Hex.decodeHex("000400".toCharArray()))
    stream.write(byteArrayOf(0x04, 0x00))
    assertThat(stream.readAllQuicMessages()[0].data).isEqualTo(Hex.decodeHex("0400".toCharArray()))
  }

  @Test
  @Throws(Exception::class)
  fun `Settingをwriteできること`() {
    val stream = ControlWriteStream(StreamId.of(0x2L))
    stream.write(Setting.builder().qpackMaxTableCapacity(100).build())
    assertThat(stream.readAllQuicMessages()[0].data)
      .isEqualTo(Hex.decodeHex("000403014064".toCharArray()))
  }
}
