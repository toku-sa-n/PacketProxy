package packetproxy.quic.utils

class Constants {
  enum class Role {
    CLIENT,
    SERVER,
  }

  enum class QuicPacketType {
    PacketInitial,
    PacketHandshake,
    PacketZeroRTT,
    PacketApplication,
  }

  enum class PnSpaceType {
    PnSpaceInitial,
    PnSpaceHandshake,
    PnSpaceApplicationData,
  }

  companion object {
    const val CONNECTION_ID_SIZE = 8
    const val TOKEN_SIZE = 16
    const val kGranularity = 1L
    const val kTimeThreshold = 9f / 8f
    const val kPacketThreshold = 3L
  }
}
