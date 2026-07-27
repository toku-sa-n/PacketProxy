package packetproxy.quic.service.key

import java.util.Optional
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.ConnectionId
import packetproxy.quic.value.key.level.*

class RoleKeys(val role: Constants.Role) {
  private var optionalInitialKey: Optional<InitialKey> = Optional.empty()
  private var optionalZeroRttKey: Optional<ZeroRttKey> = Optional.empty()
  private var optionalHandshakeKey: Optional<HandshakeKey> = Optional.empty()
  private var optionalApplicationKey: Optional<ApplicationKey> = Optional.empty()
  private var discardedInitialKeyFlag = false
  private var discardedHandshakeKeyFlag = false
  val initialKey
    get() = optionalInitialKey.orElseThrow()

  val handshakeKey
    get() = optionalHandshakeKey.orElseThrow()

  val zeroRttKey
    get() = optionalZeroRttKey.orElseThrow()

  val applicationKey
    get() = optionalApplicationKey.orElseThrow()

  fun hasInitialKey() = optionalInitialKey.isPresent

  fun hasHandshakeKey() = optionalHandshakeKey.isPresent

  fun hasZeroRttKey() = optionalZeroRttKey.isPresent

  fun hasApplicationKey() = optionalApplicationKey.isPresent

  fun computeInitialKey(id: ConnectionId) {
    optionalInitialKey = Optional.of(InitialKey.of(role, id))
  }

  fun computeZeroRttKey(secret: ByteArray) {
    optionalZeroRttKey = Optional.of(ZeroRttKey.of(secret))
  }

  fun computeHandshakeKey(secret: ByteArray) {
    optionalHandshakeKey = Optional.of(HandshakeKey.of(secret))
  }

  fun computeApplicationKey(secret: ByteArray) {
    optionalApplicationKey = Optional.of(ApplicationKey.of(secret))
  }

  fun discardInitialKey() {
    optionalInitialKey = Optional.empty()
    discardedInitialKeyFlag = true
  }

  fun discardHandshakeKey() {}

  fun discardedInitialKey() = discardedInitialKeyFlag

  fun discardedHandshakeKey() = discardedHandshakeKeyFlag
}
