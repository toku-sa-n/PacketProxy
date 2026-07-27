package packetproxy.quic.service

import java.time.Instant
import packetproxy.quic.service.connection.Connection
import packetproxy.quic.utils.Constants.PnSpaceType.PnSpaceApplicationData
import packetproxy.quic.utils.Constants.PnSpaceType.PnSpaceHandshake
import packetproxy.quic.utils.Constants.PnSpaceType.PnSpaceInitial
import packetproxy.quic.utils.ScheduledTimer
import packetproxy.quic.value.frame.PingFrame

class LossDetection(private val conn: Connection) {
  private val scheduledTimer = ScheduledTimer { onLossDetectionTimeout() }

  @Synchronized
  fun setLossDetectionTimer() {
    val t = conn.pnSpaces.earliestLossTime
    if (t != Instant.MAX) {
      scheduledTimer.update(t)
      return
    }
    if (conn.serverAntiAmplifiedLimit) {
      scheduledTimer.cancel()
      return
    }
    if (!conn.pnSpaces.hasAnyAckElicitingPacket() && conn.peerCompletedAddressValidation()) {
      scheduledTimer.cancel()
      return
    }
    scheduledTimer.update(conn.pto.ptoTime)
  }

  @Synchronized
  private fun onLossDetectionTimeout() {
    val pair = conn.pnSpaces.earliestLossTimeAndSpace
    if (pair.left != Instant.MAX) {
      val lost = conn.getPnSpace(pair.right).detectAndRemoveLostPackets()
      assert(!lost.isEmpty())
      conn.getPnSpace(pair.right).OnPacketsLost(lost)
      setLossDetectionTimer()
      return
    }
    if (!conn.pnSpaces.hasAnyAckElicitingPacket() && conn.peerAwaitingAddressValidation()) {
      if (conn.handshakeState.hasHandshakeKeys())
        conn.getPnSpace(PnSpaceHandshake).addSendFrame(PingFrame.generate())
      else conn.getPnSpace(PnSpaceInitial).addSendFrame(PingFrame.generate())
    } else if (conn.pnSpaces.hasAnyAckElicitingPacket()) {
      val s = conn.pto.ptoSpaceType
      if (conn.handshakeState.isConfirmed() && s == PnSpaceApplicationData)
        conn.getPnSpace(s).addSendFrame(PingFrame.generate())
      else if (conn.handshakeState.isAckReceived() && s == PnSpaceHandshake)
        conn.getPnSpace(s).addSendFrame(PingFrame.generate())
    }
    conn.pto.incrementPtoCount()
    setLossDetectionTimer()
  }
}
