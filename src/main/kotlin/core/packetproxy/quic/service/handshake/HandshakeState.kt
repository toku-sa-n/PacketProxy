package packetproxy.quic.service.handshake
class HandshakeState {
  enum class State {
    Initial,
    HasHandshakeKeys,
    AckReceived,
    HasAppKeys,
    Confirmed,
  }

  private var state = State.Initial

  fun transit(s: State) {
    state = s
  }

  fun hasNoHandshakeKeys() = state.ordinal < State.HasHandshakeKeys.ordinal

  fun hasHandshakeKeys() = state.ordinal >= State.HasHandshakeKeys.ordinal

  fun isAckReceived() = state.ordinal >= State.AckReceived.ordinal

  fun isNotConfirmed() = state.ordinal < State.Confirmed.ordinal

  fun isConfirmed() = state.ordinal >= State.Confirmed.ordinal
}
