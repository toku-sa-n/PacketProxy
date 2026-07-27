package packetproxy.quic.service.pnspace.helper

import java.util.ArrayDeque
import java.util.ArrayList
import packetproxy.quic.service.frame.Frames
import packetproxy.quic.value.frame.Frame

class SendFrameQueue {
  private val frames = ArrayDeque<Frame>()

  @Synchronized
  fun add(frame: Frame) {
    frames.add(frame)
  }

  @Synchronized
  fun add(frames: Frames) {
    this.frames.addAll(frames.frames)
  }

  @Synchronized
  fun pollAll(): List<Frame> {
    val r = ArrayList<Frame>()
    while (true) {
      val f = frames.poll() ?: break
      r.add(f)
    }
    return r
  }

  @Synchronized
  fun clear() {
    frames.clear()
  }
}
