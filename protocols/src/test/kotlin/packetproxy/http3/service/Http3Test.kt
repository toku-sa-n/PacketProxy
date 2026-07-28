package packetproxy.http3.service

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import packetproxy.common.UniqueID
import packetproxy.quic.value.StreamId

class Http3Test {
  @Test
  @Throws(Exception::class)
  fun `HttpとHttpRawが相互に変換できること`() {
    val http3 = Http3(UniqueID())
    val input =
      HttpRaw.of(
        StreamId.of(0L),
        Hex.decodeHex(
          "0000d1508b9c475cbe474d612af5153fd7518860d5485f2bce9a685f5088c6cfe96c3b015c1f"
        ),
        ByteArray(0),
      )
    val output = http3.generateHttpRaw(http3.generateReqHttp(input))
    assertThat(output.encodedHeader).isEqualTo(input.encodedHeader)
  }
}
