package packetproxy.quic.value.transportparameter

import java.nio.ByteBuffer
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.VariableLengthInteger

abstract class TransportParameter
protected constructor(
  protected open var parameterId: Long,
  protected open var parameterLength: Long,
  protected open var parameterValue: ByteArray,
) {
  protected constructor(buffer: ByteBuffer) : this(0, 0, byteArrayOf()) {
    parameterId = VariableLengthInteger.parse(buffer).value
    parameterLength = VariableLengthInteger.parse(buffer).value
    parameterValue = SimpleBytes.parse(buffer, parameterLength.toLong()).bytes
  }

  fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(4096)
    buffer.put(VariableLengthInteger.of(parameterId).bytes)
    buffer.put(VariableLengthInteger.of(parameterLength).bytes)
    buffer.put(parameterValue)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }
}
