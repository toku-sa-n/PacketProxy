package packetproxy.http3.value.frame

import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import packetproxy.http3.service.frame.FrameParser
import packetproxy.util.Logging

class SettingsFrameTest {
  @Test
  @Throws(Exception::class)
  fun `デフォルト値を追加したときgetBytesで値が消えること`() =
    assertThat(SettingsFrame.parse(ByteBuffer.wrap(Hex.decodeHex("040401000700"))).getBytes())
      .isEqualTo(Hex.decodeHex("0400"))

  @Test
  @Throws(Exception::class)
  fun `Qpackフレームサイズに値を入れてパースしても元に戻ること`() =
    assertThat(SettingsFrame.parse(ByteBuffer.wrap(Hex.decodeHex("0402010a"))).getBytes())
      .isEqualTo(Hex.decodeHex("0402010a"))

  @Test
  @Throws(Exception::class)
  fun `デフォルト設定でSettingsFrameを生成できること`() =
    assertThat(SettingsFrame.generateSettingsFrameWithDefaultValue().getBytes())
      .isEqualTo(Hex.decodeHex("0400"))

  @Test
  @Throws(Exception::class)
  fun `curlのSettingsFrameをパースできること`() =
    assertThat(
        SettingsFrame.parse(ByteBuffer.wrap(Hex.decodeHex("040f06ffffffffffffffff010007003300")))
          .getBytes()
      )
      .isEqualTo(Hex.decodeHex("040906ffffffffffffffff"))

  @Test
  @Throws(Exception::class)
  fun `www_google_comのSettingをパースできること2`() {
    val frames =
      FrameParser.parse(
        ByteBuffer.wrap(
          Hex.decodeHex(
            "041F018001000006800100000740640801C000001647FE8F66C000000068F2C54CC00000033AFE7BAE032CAD74"
          )
        )
      )
    assertThat(frames.size()).isEqualTo(2)
    assertThat(frames[0]).isInstanceOf(SettingsFrame::class.java)
    assertThat(frames[1]).isInstanceOf(GreaseFrame::class.java)
    Logging.log(frames)
  }
}
