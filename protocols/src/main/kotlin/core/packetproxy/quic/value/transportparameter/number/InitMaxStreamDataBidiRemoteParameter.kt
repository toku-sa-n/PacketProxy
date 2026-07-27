package packetproxy.quic.value.transportparameter.number

import java.nio.ByteBuffer
import packetproxy.quic.value.VariableLengthInteger
import packetproxy.quic.value.transportparameter.TransportParameter

class InitMaxStreamDataBidiRemoteParameter : TransportParameter {
  val value: Long

  constructor(buffer: ByteBuffer) : super(buffer) {
    this.value = VariableLengthInteger.parse(super.parameterValue).value
  }

  constructor(
    value: Long
  ) : super(
    ID,
    VariableLengthInteger.of(value).bytes.size.toLong(),
    VariableLengthInteger.of(value).bytes,
  ) {
    this.value = value
  }

  companion object {
    const val ID = 0x6L
  }
}
