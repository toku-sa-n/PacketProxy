package packetproxy.quic.value.transportparameter.complex

import java.nio.ByteBuffer
import packetproxy.quic.value.transportparameter.TransportParameter

class PreferredAddressParameter(buffer: ByteBuffer) : TransportParameter(buffer) {
  val value: ByteArray
    get() = parameterValue

  companion object {
    const val ID = 0xdL
  }
}
