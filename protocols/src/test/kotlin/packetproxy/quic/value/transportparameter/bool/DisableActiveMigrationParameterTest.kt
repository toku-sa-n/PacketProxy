package packetproxy.quic.value.transportparameter.bool

import org.apache.commons.codec.binary.Hex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

class DisableActiveMigrationParameterTest {

  @Test
  fun smoke() {
    val param = DisableActiveMigrationParameter()
    assertArrayEquals(Hex.decodeHex("0c00".toCharArray()), param.getBytes())
  }
}
