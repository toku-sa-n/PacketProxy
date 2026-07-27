package packetproxy.quic.value.transportparameter.bool

import org.apache.commons.codec.binary.Hex
import org.junit.jupiter.api.Test
import packetproxy.util.Logging

class DisableActiveMigrationParameterTest {

  @Test
  fun smoke() {
    val param = DisableActiveMigrationParameter()
    Logging.log(Hex.encodeHexString(param.getBytes()))
  }
}
