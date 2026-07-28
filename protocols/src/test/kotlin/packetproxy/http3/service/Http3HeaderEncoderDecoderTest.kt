package packetproxy.http3.service

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.eclipse.jetty.http.HttpFields
import org.eclipse.jetty.http.MetaData
import org.junit.jupiter.api.Test
import packetproxy.http3.helper.Http3TestHelper
import packetproxy.util.Logging

class Http3HeaderEncoderDecoderTest {
  @Test
  @Throws(Exception::class)
  fun `ヘッダをencode後decodeできること`() {
    val encoder = Http3HeaderEncoder(1000)
    val decoder = Http3HeaderDecoder()
    val input = Http3TestHelper().generateTestMetaData()
    val encoded = encoder.encode(0, input)
    decoder.putInstructions(encoder.getInstructions())
    decoder.decode(0, encoded).forEach { Logging.log((it.fields as HttpFields).toString()) }
    encoder.putInstructions(decoder.getInstructions())
  }

  @Test
  @Throws(Exception::class)
  fun `getInstructionsすると命令が消費されること`() {
    val encoder = Http3HeaderEncoder(1000)
    encoder.encode(0, Http3TestHelper().generateTestMetaData())
    assertThat(encoder.getInstructions()).isNotEmpty()
    assertThat(encoder.getInstructions()).isEmpty()
  }

  @Test
  fun `capacityのデバッグ`() {
    listOf(0, 1, 10, 1000).forEach {
      Logging.log(Hex.encodeHexString(Http3HeaderEncoder(it.toLong()).getInstructions()))
    }
  }

  @Test
  @Throws(Exception::class)
  fun `サンプルデータをデコードする`() {
    val bytes =
      Hex.decodeHex(
        "0000d1d7510b2f696e6465782e68746d6c500f68326f2e6578616d7031652e6e65745f500a48335a65726f2f312e30"
      )
    val decoder = Http3HeaderDecoder()
    decoder.decode(0, bytes).forEach { output ->
      if (output.isRequest) {
        val request = output as MetaData.Request
        Logging.log("%s %s %s%n", request.method, request.uri.path, request.httpVersion)
        request.fields.forEach { Logging.log("%s: %s%n", it.name, it.value) }
      }
    }
    assertThat(decoder.getInstructions().size).isZero()
  }
}
