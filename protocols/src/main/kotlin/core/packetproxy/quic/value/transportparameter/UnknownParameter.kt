package packetproxy.quic.value.transportparameter

import java.nio.ByteBuffer

class UnknownParameter : TransportParameter {
  constructor(buffer: ByteBuffer) : super(buffer)

  constructor(unknownBytes: ByteArray) : super(ID, unknownBytes.size.toLong(), unknownBytes)

  val value: ByteArray
    get() = parameterValue

  companion object {
    const val ID = 0xdeadbeefL
  }
}
