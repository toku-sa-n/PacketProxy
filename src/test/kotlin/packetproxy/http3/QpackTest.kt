package packetproxy.http3

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.eclipse.jetty.http.HttpFields
import org.eclipse.jetty.http.HttpURI
import org.eclipse.jetty.http.HttpVersion
import org.eclipse.jetty.http.MetaData
import org.eclipse.jetty.http3.qpack.QpackDecoder
import org.eclipse.jetty.http3.qpack.QpackEncoder
import org.eclipse.jetty.io.ByteBufferPool
import org.eclipse.jetty.io.MappedByteBufferPool
import org.junit.jupiter.api.Test
import packetproxy.common.Binary
import packetproxy.http.Http
import packetproxy.quic.value.SimpleBytes
import packetproxy.util.Logging

class QpackTest {
  @Test
  @Throws(Exception::class)
  fun smoke() {
    val lease = ByteBufferPool.Lease(MappedByteBufferPool())
    val encoder = QpackEncoder({ instructions -> instructions.forEach { it.encode(lease) } }, 100)
    encoder.setCapacity(100)
    val fields = HttpFields.build().add("hoge", "fuga")
    val buffer = ByteBuffer.allocate(1024)
    encoder.encode(buffer, 0, MetaData(HttpVersion.HTTP_3, fields))
    buffer.flip()
    Logging.log(Binary(SimpleBytes.parse(buffer, buffer.remaining()).bytes).toHexString())
    buffer.clear()
    encoder.encode(buffer, 0xb, MetaData(HttpVersion.HTTP_3, fields))
    buffer.flip()
    Logging.log(Binary(SimpleBytes.parse(buffer, buffer.remaining()).bytes).toHexString())
    val instructions = ByteArrayOutputStream()
    lease.byteBuffers.forEach { instructions.write(SimpleBytes.parse(it, it.remaining()).bytes) }
    Logging.log(
      "send: QpackEncoder Instructions: ${Hex.encodeHexString(instructions.toByteArray())}"
    )
  }

  @Test
  @Throws(Exception::class)
  fun `QpackEncoderとQpackDecoderのテスト`() {
    val lease = ByteBufferPool.Lease(MappedByteBufferPool())
    val lease2 = ByteBufferPool.Lease(MappedByteBufferPool())
    val encoder = QpackEncoder({ instructions -> instructions.forEach { it.encode(lease) } }, 100)
    val decoder = QpackDecoder({ instructions -> instructions.forEach { it.encode(lease2) } }, 100)
    encoder.setCapacity(100)
    val fields = HttpFields.build().add("hoge", "fuga")
    val buffer = ByteBuffer.allocate(1024)
    encoder.encode(buffer, 0, MetaData(HttpVersion.HTTP_3, fields))
    buffer.flip()
    val headers = SimpleBytes.parse(buffer, buffer.remaining()).bytes
    val encoderInstructions = ByteArrayOutputStream()
    lease.byteBuffers.forEach {
      encoderInstructions.write(SimpleBytes.parse(it, it.remaining()).bytes)
    }
    decoder.parseInstructions(ByteBuffer.wrap(encoderInstructions.toByteArray()))
    decoder.decode(0, ByteBuffer.wrap(headers)) { _, metadata ->
      assertThat(fields.asImmutable()).isEqualTo(metadata.fields)
    }
    val decoderInstructions = ByteArrayOutputStream()
    lease2.byteBuffers.forEach {
      decoderInstructions.write(SimpleBytes.parse(it, it.remaining()).bytes)
    }
    encoder.parseInstructions(ByteBuffer.wrap(decoderInstructions.toByteArray()))
  }

  @Test
  @Throws(Exception::class)
  fun metaDataTest() {
    val http =
      Http.create(
        "POST / HTTP/3\nhost: localhost\nx-hoge: fuga\n\nThis is a post data.".toByteArray()
      )
    val fields = HttpFields.build()
    http.header.fields.forEach { fields.add(it.getName(), it.getValue()) }
    Logging.log(
      MetaData.Request(http.method, HttpURI.from("https://localhost/"), HttpVersion.HTTP_3, fields)
    )
  }
}
