package packetproxy.quic.service

import java.time.Duration
import java.time.Instant
import kotlin.math.min
import packetproxy.quic.service.connection.Connection
import packetproxy.quic.utils.Constants

class RttEstimator(private val conn: Connection) {
  private val initialRtt = 333L
  private var first = Instant.MIN
  var minRtt = 0L
    private set

  var smoothedRtt = initialRtt
    private set

  var rttVar = initialRtt / 2
    private set

  var latestRtt = 0L
    private set

  var maxAckDelay = 25L
    private set

  fun updateRtt(timeSent: Instant, ackDelay: Long) {
    val now = Instant.now()
    latestRtt = Duration.between(now, timeSent).toMillis()
    if (first == Instant.MIN) {
      minRtt = latestRtt
      smoothedRtt = latestRtt
      rttVar = latestRtt / 2
      first = now
    }
    minRtt = min(minRtt, latestRtt)
    var d = ackDelay
    if (conn.handshakeState.isConfirmed()) d = min(ackDelay, maxAckDelay)
    var adj = latestRtt
    if (latestRtt >= minRtt + d) adj = latestRtt - d
    val cur = kotlin.math.abs(smoothedRtt - adj)
    rttVar = (3 * rttVar + cur) / 4
    smoothedRtt = (7 * smoothedRtt + adj) / 8
  }

  fun getLossDelay() = (Constants.kTimeThreshold * maxOf(latestRtt, smoothedRtt)).toLong()
}
