package packetproxy.quic.service.packet

import java.net.DatagramPacket
import java.nio.ByteBuffer
import java.util.Optional
import packetproxy.quic.service.connection.Connection
import packetproxy.quic.service.key.RoleKeys
import packetproxy.quic.utils.AwaitingException
import packetproxy.quic.utils.Constants.PnSpaceType.*
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.packet.QuicPacket
import packetproxy.quic.value.packet.longheader.LongHeaderPacket
import packetproxy.quic.value.packet.longheader.pnspace.HandshakePacket
import packetproxy.quic.value.packet.longheader.pnspace.InitialPacket
import packetproxy.quic.value.packet.longheader.pnspace.ZeroRttPacket
import packetproxy.quic.value.packet.shortheader.ShortHeaderPacket

class QuicPacketParser(private val conn: Connection, private val roleKeys: RoleKeys) {
  @Throws(Exception::class)
  fun parseOnePacket(udp: DatagramPacket) {
    val buffer = ByteBuffer.wrap(udp.data)
    while (buffer.hasRemaining()) parse(buffer).ifPresent { conn.pnSpaces.receivePacket(it) }
  }

  @Throws(Exception::class)
  private fun parse(buffer: ByteBuffer): Optional<QuicPacket> {
    val type = getType(buffer)
    return when {
      InitialPacket.`is`(type) && roleKeys.hasInitialKey() ->
        Optional.of(
          InitialPacket(
            buffer,
            roleKeys.initialKey,
            conn.getPnSpace(PnSpaceInitial).ackFrameGenerator.getLargestAckedPn(),
          )
        )
      HandshakePacket.`is`(type) && roleKeys.hasHandshakeKey() ->
        Optional.of(
          HandshakePacket(
            buffer,
            roleKeys.handshakeKey,
            conn.getPnSpace(PnSpaceHandshake).ackFrameGenerator.getLargestAckedPn(),
          )
        )
      ShortHeaderPacket.`is`(type) && roleKeys.hasApplicationKey() ->
        Optional.of(
          ShortHeaderPacket(
            buffer,
            roleKeys.applicationKey,
            conn.getPnSpace(PnSpaceApplicationData).ackFrameGenerator.getLargestAckedPn(),
          )
        )
      ZeroRttPacket.`is`(type) && roleKeys.hasZeroRttKey() ->
        Optional.of(
          ZeroRttPacket(
            buffer,
            roleKeys.zeroRttKey,
            conn.getPnSpace(PnSpaceApplicationData).ackFrameGenerator.getLargestAckedPn(),
          )
        )
      type.toInt() == 0x0 -> {
        buffer.position(buffer.limit())
        Optional.empty()
      }
      else -> {
        if (InitialPacket.`is`(type))
          throw AwaitingException("InitialPacket has been received, but initial key was not found")
        if (HandshakePacket.`is`(type))
          throw AwaitingException("wait until deploying handshake key")
        if (ShortHeaderPacket.`is`(type) || ZeroRttPacket.`is`(type))
          throw AwaitingException("wait until deploying application key")
        throw Exception(String.format("Unknown Error: packet type (%x) received", type))
      }
    }
  }

  companion object {
    @Throws(Exception::class)
    @JvmStatic
    fun getDestConnectionId(bytes: ByteArray) = getDestConnectionId(ByteBuffer.wrap(bytes))

    @Throws(Exception::class)
    @JvmStatic
    fun getDestConnectionId(buffer: ByteBuffer): ConnectionId {
      val type = getType(buffer)
      return when {
        LongHeaderPacket.`is`(type) -> LongHeaderPacket.getDestConnId(buffer)
        ShortHeaderPacket.`is`(type) -> ShortHeaderPacket.getDestConnId(buffer)
        else -> throw Exception("Error: unknown packet (LongHeaderPacket nor ShortHeaderPacket)")
      }
    }

    private fun getType(buffer: ByteBuffer): Byte {
      val pos = buffer.position()
      val t = buffer.get()
      buffer.position(pos)
      return t
    }
  }
}
