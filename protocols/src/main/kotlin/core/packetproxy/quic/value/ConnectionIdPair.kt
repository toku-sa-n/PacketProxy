package packetproxy.quic.value

data class ConnectionIdPair(val srcConnId: ConnectionId, val destConnId: ConnectionId) {
  companion object {
    @JvmStatic
    fun of(srcConnId: ConnectionId, destConnId: ConnectionId) =
      ConnectionIdPair(srcConnId, destConnId)

    @JvmStatic
    fun generateRandom() = of(ConnectionId.generateRandom(), ConnectionId.generateRandom())
  }
}
