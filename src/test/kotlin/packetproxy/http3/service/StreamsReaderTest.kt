package packetproxy.http3.service

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.QuicMessages
import packetproxy.quic.value.StreamId

class StreamsReaderTest {
  @Test
  @Throws(Exception::class)
  fun `SettingsFrameを読み込めること`() {
    val streams = StreamsReader(Constants.Role.CLIENT)
    streams.write(
      QuicMessages.of(QuicMessage.of(StreamId.of(0x2L), Hex.decodeHex("00040401000700")))
    )
    val settings = streams.getSetting().orElseThrow()
    assertThat(settings.qpackMaxTableCapacity).isZero()
    assertThat(settings.maxFieldSectionSize).isEqualTo(Long.MAX_VALUE)
  }
}
