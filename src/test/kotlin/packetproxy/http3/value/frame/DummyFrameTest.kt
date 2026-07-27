package packetproxy.http3.value.frame

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DummyFrameTest {
  @Test
  @Throws(Exception::class)
  fun `値1を保存できること`() = assertThat(DummyFrame.of(1).getBytes()).isEqualTo(Hex.decodeHex("3301"))

  @Test
  @Throws(Exception::class)
  fun `値2を保存できること`() = assertThat(DummyFrame.of(2).getBytes()).isEqualTo(Hex.decodeHex("3302"))
}
