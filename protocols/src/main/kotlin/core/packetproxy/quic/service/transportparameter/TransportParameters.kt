package packetproxy.quic.service.transportparameter

import java.nio.ByteBuffer
import net.luminis.tls.extension.Extension
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.transportparameter.*
import packetproxy.quic.value.transportparameter.bool.DisableActiveMigrationParameter
import packetproxy.quic.value.transportparameter.bool.ExpGreaseQuicBitParameter
import packetproxy.quic.value.transportparameter.bytearray.*
import packetproxy.quic.value.transportparameter.complex.PreferredAddressParameter
import packetproxy.quic.value.transportparameter.number.*
import packetproxy.util.err

class TransportParameters(val role: Constants.Role) : Extension() {
  var initMaxData = 0L
  var initMaxStreamDataBidiLocal = 0L
  var initMaxStreamDataBidiRemote = 0L
  var initMaxStreamBidi = 0L
  var initMaxStreamDataUni = 0L
  var initMaxStreamUni = 0L
  var initSrcConnId = ByteArray(0)
  var ackDelayExponent = 3L
  var activeConnIdLimit = 2L
  var disableActiveMigration = false
  var maxAckDelay = 25L
  var oldMinAckDelay = 0L
  var expMinAckDelay = 0L
  var maxIdleTimeout = 0L
  var maxUdpPayloadSize = 65527L
  var origDestConnId = ByteArray(0)
  var preferredAddress = ByteArray(0)
  var retrySrcConnId = ByteArray(0)
  var statelessResetToken = ByteArray(0)
  var oldTimestamp = 0L
  var expGreaseQuicBit = false

  constructor(role: Constants.Role, bytes: ByteArray) : this(role, ByteBuffer.wrap(bytes))

  constructor(role: Constants.Role, buffer: ByteBuffer) : this(role) {
    val type = buffer.short
    if (type.toInt() != 0x39)
      throw Exception(String.format("[Error] not TransportParameterExtension (type: %04x)", type))
    val length = buffer.short
    if (length.toInt() == 0) return
    val end = buffer.position() + length
    val transportParameterParser = TransportParameterParser()
    while (buffer.position() < end) setLocal(transportParameterParser.parse(buffer))
  }

  private fun setLocal(param: TransportParameter) =
    when (param) {
      is InitMaxStreamDataBidiLocalParameter -> initMaxStreamDataBidiLocal = param.value
      is InitMaxStreamDataBidiRemoteParameter -> initMaxStreamDataBidiRemote = param.value
      is InitMaxStreamDataUniParameter -> initMaxStreamDataUni = param.value
      is InitMaxStreamBidiParameter -> initMaxStreamBidi = param.value
      is InitMaxStreamUniParameter -> initMaxStreamUni = param.value
      is InitMaxDataParameter -> initMaxData = param.value
      is InitSrcConnIdParameter -> initSrcConnId = param.value
      is AckDelayExponentParameter -> ackDelayExponent = param.value
      is ActiveConnIdLimitParameter -> activeConnIdLimit = param.value
      is DisableActiveMigrationParameter -> disableActiveMigration = true
      is MaxAckDelayParameter -> maxAckDelay = param.value
      is MaxIdleTimeoutParameter -> maxIdleTimeout = param.value
      is MaxUdpPayloadSizeParameter -> maxUdpPayloadSize = param.value
      is OrigDestConnIdParameter -> origDestConnId = param.value
      is PreferredAddressParameter -> preferredAddress = param.value
      is RetrySrcConnIdParameter -> retrySrcConnId = param.value
      is StatelessResetTokenParameter -> statelessResetToken = param.value
      is OldMinAckDelayParameter -> oldMinAckDelay = param.value
      is ExpMinAckDelayParameter -> expMinAckDelay = param.value
      is OldTimestampParameter -> oldTimestamp = param.value
      is ExpGreaseQuicBitParameter -> expGreaseQuicBit = true
      is UnknownParameter -> err("[Error] Unknown Transport Parameter: %s", param)
      else -> {}
    }

  override fun getBytes(): ByteArray {
    val params = ByteBuffer.allocate(1500)
    params.put(MaxUdpPayloadSizeParameter(maxUdpPayloadSize).getBytes())
    params.put(InitSrcConnIdParameter(initSrcConnId).getBytes())
    params.put(InitMaxDataParameter(initMaxData).getBytes())
    params.put(InitMaxStreamUniParameter(initMaxStreamUni).getBytes())
    params.put(InitMaxStreamBidiParameter(initMaxStreamBidi).getBytes())
    params.put(InitMaxStreamDataBidiLocalParameter(initMaxStreamDataBidiLocal).getBytes())
    params.put(InitMaxStreamDataBidiRemoteParameter(initMaxStreamDataBidiRemote).getBytes())
    params.put(InitMaxStreamDataUniParameter(initMaxStreamDataUni).getBytes())
    params.put(AckDelayExponentParameter(ackDelayExponent).getBytes())
    params.put(MaxIdleTimeoutParameter(maxIdleTimeout).getBytes())
    if (role == Constants.Role.SERVER) {
      params.put(OrigDestConnIdParameter(origDestConnId).getBytes())
      params.put(ActiveConnIdLimitParameter(activeConnIdLimit).getBytes())
      if (disableActiveMigration) params.put(DisableActiveMigrationParameter().getBytes())
    }
    params.flip()
    val buffer = ByteBuffer.allocate(1500)
    buffer.putShort(0x39)
    buffer.putShort(params.remaining().toShort())
    buffer.put(SimpleBytes.parse(params, params.remaining().toLong()).bytes)
    buffer.flip()
    return SimpleBytes.parse(buffer, buffer.remaining().toLong()).bytes
  }
}
