package packetproxy.quic.service.pnspace

import java.io.OutputStream
import java.time.Instant
import packetproxy.quic.service.connection.Connection
import packetproxy.quic.service.frame.Frames
import packetproxy.quic.service.frame.FramesBuilder
import packetproxy.quic.service.framegenerator.*
import packetproxy.quic.service.handshake.HandshakeState.State.Confirmed
import packetproxy.quic.service.packet.QuicPacketBuilder
import packetproxy.quic.service.pnspace.helper.*
import packetproxy.quic.utils.Constants
import packetproxy.quic.utils.Constants.PnSpaceType
import packetproxy.quic.utils.Constants.PnSpaceType.*
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.SentPacket
import packetproxy.quic.value.frame.*
import packetproxy.quic.value.packet.PnSpacePacket
import packetproxy.quic.value.packet.QuicPacket
import packetproxy.util.Logging.err
import packetproxy.util.Throwing.rethrow

abstract class PnSpace(protected val conn: Connection, val pnSpaceType: PnSpaceType) {
  val frameToMsgCryptoStream = CryptoFramesToMessages()
  val msgToFrameCryptoStream = MessagesToCryptoFrames()
  val frameToMsgStream = StreamFramesToMessages()
  val ackFrameGenerator = AckFrameGenerator()
  val sentPackets = SentPackets()
  val sendFrameQueue = SendFrameQueue()
  var largestAckedPn = PacketNumber.Infinite
  var lossTime = Instant.MAX
  var timeOfLastAckElicitingPacket = Instant.MIN
  private var nextPacketNumber = PacketNumber.of(0)

  fun getNextPacketNumberAndIncrement(): PacketNumber = nextPacketNumberAndIncrement()

  fun nextPacketNumberAndIncrement(): PacketNumber {
    val pn = PacketNumber.copy(nextPacketNumber)
    nextPacketNumber = nextPacketNumber.plus(1)
    return pn
  }

  @Synchronized fun hasAnyAckElicitingPacket() = sentPackets.hasAnyAckElicitingPacket()

  @Synchronized
  fun close() {
    sentPackets.clear()
    sendFrameQueue.clear()
    lossTime = Instant.MAX
    timeOfLastAckElicitingPacket = Instant.MIN
  }

  @Synchronized
  fun OnAckReceived(pn: PacketNumber, ackFrame: AckFrame) {
    largestAckedPn =
      if (largestAckedPn == PacketNumber.Infinite) ackFrame.largestAckedPn
      else PacketNumber.max(largestAckedPn, ackFrame.largestAckedPn)
    val newly = sentPackets.detectAndRemoveAckedPackets(ackFrame)
    if (newly.isEmpty()) return
    newly.getLargest().ifPresent {
      if (it.packetNumber == ackFrame.largestAckedPn && newly.hasAnyAckElicitingPacket())
        conn.rttEstimator.updateRtt(it.timeSent, ackFrame.ackDelay)
    }
    val lost = detectAndRemoveLostPackets()
    if (!lost.isEmpty()) OnPacketsLost(lost)
    if (conn.peerCompletedAddressValidation()) conn.pto.clearPtoCount()
    conn.lossDetection.setLossDetectionTimer()
  }

  @Synchronized
  open fun receivePacket(quicPacket: QuicPacket) {
    if (quicPacket is PnSpacePacket) {
      ackFrameGenerator.received(quicPacket.packetNumber)
      if (quicPacket.isAckEliciting()) {
        val ack = ackFrameGenerator.generateAckFrame()
        if (ack != null) addSendFrameFirst(ack)
      }
      receiveFrames(quicPacket.packetNumber, quicPacket.frames)
    }
  }

  @Synchronized
  private fun receiveFrames(pn: PacketNumber, frames: Frames) {
    for (frame in frames) when (frame) {
      is CryptoFrame -> {
        frameToMsgCryptoStream.write(frame)
        frameToMsgCryptoStream
          .getHandshakeMessages()
          .forEach(rethrow { conn.handshake.received(it) })
      }
      is StreamFrame -> {
        frameToMsgStream.put(frame)
        frameToMsgStream
          .get(frame.streamId)
          .ifPresent(
            rethrow { msg ->
              val os: OutputStream = conn.pipe.getRawEndpoint().getOutputStream()
              os.write(msg.data)
              os.flush()
            }
          )
      }
      is AckFrame -> OnAckReceived(pn, frame)
      is HandshakeDoneFrame -> {
        conn.handshakeState.transit(Confirmed)
        if (conn.role == Constants.Role.CLIENT) {
          conn.keys.discardInitialKey()
          conn.getPnSpace(PnSpaceInitial).close()
          conn.keys.discardHandshakeKey()
          conn.getPnSpace(PnSpaceHandshake).close()
        }
      }
      is ConnectionCloseFrame -> {
        err("HTTP3 connection closed (%s)", frame.reasonPhraseString)
        conn.close()
      }
      is NewConnectionIdFrame,
      is NewTokenFrame,
      is PingFrame,
      is PaddingFrame,
      is MaxDataFrame,
      is StopSendingFrame -> {}
      is ResetStreamFrame -> conn.close()
      else -> err("Error: cannot process frame: %s", frame)
    }
  }

  @Synchronized open fun addSendQuicMessage(msg: QuicMessage) {}

  @Synchronized
  fun addSendFrameFirst(frame: Frame?) {
    conn.pnSpaces.addSendPacketsFirst(
      QuicPacketBuilder.getBuilder()
        .setPnSpaceType(pnSpaceType)
        .setFramesBuilder(FramesBuilder().add(frame))
    )
  }

  fun addSendFrame(frame: Frame) = addSendFrames(Frames.of(frame))

  @Synchronized
  fun addSendFrames(frames: Frames) {
    sendFrameQueue.add(frames)
    conn.pnSpaces.addSendPackets(getAndRemoveSendFramesAndConvertPacketBuilders())
  }

  @Synchronized
  fun addSentPacket(quicPacket: QuicPacket) {
    if (quicPacket is PnSpacePacket) {
      sentPackets.add(SentPacket(quicPacket))
      if (quicPacket.isAckEliciting()) timeOfLastAckElicitingPacket = Instant.now()
    }
  }

  fun OnPacketsLost(lost: LostPackets) {
    lost.forEach { addSendFrames(it.packet.frames) }
  }

  @Synchronized
  fun detectAndRemoveLostPackets(): LostPackets {
    assert(largestAckedPn != PacketNumber.Infinite)
    lossTime = Instant.MAX
    val lost = LostPackets()
    val delay = conn.rttEstimator.getLossDelay()
    val lostSendTime = Instant.now().minusMillis(delay)
    for (unAcked in sentPackets.getUnAckedPackets()) {
      val pn = unAcked.packetNumber
      if (pn.isLargerThan(largestAckedPn)) continue
      if (
        unAcked.timeSent.isBefore(lostSendTime) ||
          largestAckedPn.isLargerThanOrEquals(pn.plus(Constants.kPacketThreshold))
      ) {
        sentPackets.removePacket(unAcked)
        lost.add(unAcked)
      } else {
        val t = unAcked.timeSent.plusMillis(delay)
        if (t.isBefore(lossTime)) lossTime = t
      }
    }
    return lost
  }

  abstract fun getAndRemoveSendFramesAndConvertPacketBuilders(): List<QuicPacketBuilder>
}
