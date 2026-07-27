package packetproxy.quic.service.frame

import java.nio.ByteBuffer
import java.util.ArrayList
import packetproxy.quic.value.SimpleBytes
import packetproxy.quic.value.frame.Frame
import packetproxy.quic.value.frame.PaddingFrame

class FramesBuilder {
  private val frames = ArrayList<Frame>()

  fun add(frame: Frame?): FramesBuilder {
    if (frame != null) frames.add(frame)
    return this
  }

  fun addPaddingFramesToEnsure1200Bytes(): FramesBuilder {
    val pad = 1200 - getBytes().size
    if (pad > 0) add(PaddingFrame(pad.toLong()))
    return this
  }

  fun getBytes(): ByteArray {
    val b = ByteBuffer.allocate(1500)
    frames.forEach { b.put(it.getBytes()) }
    b.flip()
    return SimpleBytes.parse(b, b.remaining().toLong()).bytes
  }

  fun build() = Frames(frames)
}
