package packetproxy.http3.service.frame

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import packetproxy.http3.value.frame.DataFrame
import packetproxy.http3.value.frame.HeadersFrame
import packetproxy.http3.value.frame.SettingsFrame

class FrameParserTest {
  @Test
  @Throws(Exception::class)
  fun `SETTINGSフレームをパースできること`() {
    val frames = FrameParser.parse(ByteBuffer.wrap(Hex.decodeHex("0400")))
    assertThat(frames.size()).isEqualTo(1)
    assertThat(frames.toList()).anyMatch { it is SettingsFrame }
  }

  @Test
  @Throws(Exception::class)
  fun `HEADERSフレームとDATAフレームをパースできること`() {
    val frames =
      FrameParser.parse(
        ByteBuffer.wrap(
          Hex.decodeHex(
            "0140410000db5f4d929c47604bb2b816bf838ffe9c95c292523acf5401395f1d92497ca58ae819aafb50938ec415305a99567b5f448e9d983f9b8d34cff3f6a52381c00300096e6f7420666f756e64"
          )
        )
      )
    assertThat(frames.toList()).anyMatch { it is HeadersFrame }
    assertThat(frames.toList()).anyMatch { it is DataFrame }
  }

  @Test
  @Throws(Exception::class)
  fun `SETTINGSフレームをパースして元に戻ること`() {
    val input = Hex.decodeHex("0400")
    assertThat(FrameParser.parse(ByteBuffer.wrap(input))[0].getBytes()).isEqualTo(input)
  }

  @Test
  @Throws(Exception::class)
  fun `HEADERSフレームとDATAフレームをパースして元に戻ること`() {
    val input =
      Hex.decodeHex(
        "0140410000db5f4d929c47604bb2b816bf838ffe9c95c292523acf5401395f1d92497ca58ae819aafb50938ec415305a99567b5f448e9d983f9b8d34cff3f6a52381c00300096e6f7420666f756e64"
      )
    val output = ByteArrayOutputStream()
    FrameParser.parse(ByteBuffer.wrap(input)).forEach { output.write(it.getBytes()) }
    assertThat(output.toByteArray()).isEqualTo(input)
  }
}
