package packetproxy.quic.value

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class QuicMessagesTest {

  lateinit var msgs: QuicMessages

  @BeforeEach
  fun before() {
    this.msgs =
      QuicMessages.of(
        QuicMessage.of(StreamId.of(1), byteArrayOf(0x1)),
        QuicMessage.of(StreamId.of(2), byteArrayOf(0x2)),
        QuicMessage.of(StreamId.of(3), byteArrayOf(0x3)),
      )
  }

  @Test
  fun getが動作すること() {
    val msg1 = QuicMessage.of(StreamId.of(1), byteArrayOf(0x1))
    val msg2 = QuicMessage.of(StreamId.of(2), byteArrayOf(0x2))
    val msg3 = QuicMessage.of(StreamId.of(3), byteArrayOf(0x3))
    assertThat(this.msgs.get(0)).isEqualTo(msg1)
    assertThat(this.msgs.get(1)).isEqualTo(msg2)
    assertThat(this.msgs.get(2)).isEqualTo(msg3)
  }

  @Test
  fun equalsが動作すること() {
    val msgs2 =
      QuicMessages.of(
        QuicMessage.of(StreamId.of(1), byteArrayOf(0x1)),
        QuicMessage.of(StreamId.of(2), byteArrayOf(0x2)),
        QuicMessage.of(StreamId.of(3), byteArrayOf(0x3)),
      )
    assertThat(msgs2).isEqualTo(this.msgs)
  }

  @Test
  fun forEachが動作すること() {
    val collected = ArrayList<QuicMessage>()
    this.msgs.forEach { msg -> collected.add(msg) }
    assertThat(collected).hasSize(3)
    assertThat(collected[0]).isEqualTo(QuicMessage.of(StreamId.of(1), byteArrayOf(0x1)))
    assertThat(collected[1]).isEqualTo(QuicMessage.of(StreamId.of(2), byteArrayOf(0x2)))
    assertThat(collected[2]).isEqualTo(QuicMessage.of(StreamId.of(3), byteArrayOf(0x3)))
  }

  @Test
  fun filterが動作すること() {
    val filteredMsg = this.msgs.filter(StreamId.of(0x2))
    val expectedMsg = QuicMessage.of(StreamId.of(0x2), byteArrayOf(0x2))
    assertThat(filteredMsg.size()).isEqualTo(1)
    assertThat(filteredMsg.get(0)).isEqualTo(expectedMsg)
  }

  @Test
  fun filterAllButが動作すること() {
    val filteredMsg = this.msgs.filterAllBut(StreamId.of(0x2))
    val expectedMsg1 = QuicMessage.of(StreamId.of(0x1), byteArrayOf(0x1))
    val expectedMsg2 = QuicMessage.of(StreamId.of(0x3), byteArrayOf(0x3))
    assertThat(filteredMsg.size()).isEqualTo(2)
    assertThat(filteredMsg.get(0)).isEqualTo(expectedMsg1)
    assertThat(filteredMsg.get(1)).isEqualTo(expectedMsg2)
  }

  @Test
  fun getBytesが動作すること() {
    val bytes = this.msgs.getBytes()
    assertThat(bytes)
      .isEqualTo(
        Hex.decodeHex(
          "000000000000000100000000000000010100000000000000020000000000000001020000000000000003000000000000000103"
            .toCharArray()
        )
      )
  }
}
