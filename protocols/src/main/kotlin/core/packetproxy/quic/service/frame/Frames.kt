package packetproxy.quic.service.frame

import com.google.common.collect.ImmutableList
import java.nio.ByteBuffer
import java.util.ArrayList
import java.util.Optional
import packetproxy.quic.value.frame.AckFrame
import packetproxy.quic.value.frame.Frame
import packetproxy.util.errWithStackTrace

class Frames(val frames: List<Frame>) : Iterable<Frame> {
  fun isAckEliciting() = frames.any { it.isAckEliciting() }

  fun hasAckFrame() = frames.any { it is AckFrame }

  fun getAckFrame(): Optional<AckFrame> =
    frames.filterIsInstance<AckFrame>().firstOrNull()?.let { Optional.of(it) } ?: Optional.empty()

  override fun toString() = "Frames(${frames.joinToString(",") { it.toString() }})"

  override fun iterator() = frames.iterator()

  companion object {
    @JvmField val empty = Frames(ImmutableList.of())

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): Frames =
      try {
        val l = ArrayList<Frame>()
        val frameParser = FrameParser()
        while (buffer.hasRemaining()) l.add(frameParser.create(buffer))
        Frames(l)
      } catch (e: Exception) {
        errWithStackTrace(e)
        empty
      }

    @JvmStatic fun of(e1: Frame) = Frames(ImmutableList.of(e1))

    @JvmStatic fun of(e1: Frame, e2: Frame) = Frames(ImmutableList.of(e1, e2))

    @JvmStatic fun of(e1: Frame, e2: Frame, e3: Frame) = Frames(ImmutableList.of(e1, e2, e3))

    @JvmStatic fun of(frameList: List<Frame>) = Frames(ArrayList(frameList))
  }
}
