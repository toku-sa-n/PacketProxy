package packetproxy.quic.service

import java.time.Instant
import org.apache.commons.lang3.tuple.ImmutablePair
import packetproxy.quic.service.connection.Connection
import packetproxy.quic.utils.Constants
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.utils.Constants.PnSpaceType.*

class Pto(private val conn: Connection) {
  private var ptoCount = 0L

  fun clearPtoCount() {
    ptoCount = 0
  }

  fun incrementPtoCount() {
    ptoCount++
  }

  val ptoTime
    get() = ptoTimeAndSpace.left

  val ptoSpaceType
    get() = ptoTimeAndSpace.right

  val ptoTimeAndSpace: ImmutablePair<Instant, PnSpaceType>
    get() {
      var duration =
        (conn.rttEstimator.smoothedRtt +
          maxOf(4 * conn.rttEstimator.rttVar, Constants.kGranularity)) * (1L shl ptoCount.toInt())
      if (conn.peerAwaitingAddressValidation())
        return if (conn.handshakeState.hasNoHandshakeKeys())
          ImmutablePair.of(Instant.now().plusMillis(duration), PnSpaceInitial)
        else ImmutablePair.of(Instant.now().plusMillis(duration), PnSpaceHandshake)
      var timeout = Instant.MAX
      var space = PnSpaceInitial
      for (s in PnSpaceType.entries) {
        if (!conn.getPnSpace(s).hasAnyAckElicitingPacket()) continue
        if (s == PnSpaceApplicationData) {
          if (conn.handshakeState.isNotConfirmed()) return ImmutablePair.of(timeout, space)
          duration += conn.rttEstimator.maxAckDelay * (1L shl ptoCount.toInt())
        }
        val t = conn.getPnSpace(s).timeOfLastAckElicitingPacket.plusMillis(duration)
        if (t.isBefore(timeout)) {
          timeout = t
          space = s
        }
      }
      return ImmutablePair.of(timeout, space)
    }
}
