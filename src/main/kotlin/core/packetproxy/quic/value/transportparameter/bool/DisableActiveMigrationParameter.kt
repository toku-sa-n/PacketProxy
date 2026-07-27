package packetproxy.quic.value.transportparameter.bool

import java.nio.ByteBuffer
import packetproxy.quic.value.transportparameter.TransportParameter

class DisableActiveMigrationParameter : TransportParameter {
  constructor(buffer: ByteBuffer) : super(buffer)

  constructor() : super(ID, 0, ByteArray(0))

  companion object {
    const val ID = 0xcL
  }
}
