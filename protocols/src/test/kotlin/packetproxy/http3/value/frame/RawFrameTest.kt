package packetproxy.http3.value.frame

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import packetproxy.quic.value.VariableLengthInteger

class RawFrameTest {
  @Test
  @Throws(Exception::class)
  fun `RawFrameが正常に動作すること`() =
    assertThat(RawFrame.of(VariableLengthInteger.of(1).bytes).getBytes())
      .isEqualTo(Hex.decodeHex("01"))
}
