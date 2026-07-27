package packetproxy.quic.value.transportparameter.bytearray

import java.nio.ByteBuffer
import packetproxy.quic.value.transportparameter.TransportParameter

class RetrySrcConnIdParameter : TransportParameter {
  constructor(buffer: ByteBuffer) : super(buffer)

  constructor(value: ByteArray) : super(ID, value.size.toLong(), value)

  val value: ByteArray
    get() = parameterValue

  companion object {
    const val ID = 0x10L
  }
}
