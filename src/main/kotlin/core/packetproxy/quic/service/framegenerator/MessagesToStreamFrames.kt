package packetproxy.quic.service.framegenerator

import org.apache.commons.lang3.ArrayUtils
import packetproxy.quic.service.frame.Frames
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId
import packetproxy.quic.value.frame.Frame
import packetproxy.quic.value.frame.StreamFrame

class MessagesToStreamFrames {
  private val frameList = mutableListOf<Frame>()
  private val continuousStreamMap = HashMap<StreamId, Long>()

  @Synchronized
  fun put(msg: QuicMessage) {
    val streamId = msg.streamId
    val data = msg.data
    if (streamId.isBidirectional()) {
      var remaining = data.size
      var subOffset = 0
      while (remaining > 0) {
        val sub = minOf(remaining, 1200)
        frameList.add(
          StreamFrame.of(
            streamId,
            subOffset.toLong(),
            sub.toLong(),
            ArrayUtils.subarray(data, subOffset, subOffset + sub),
            subOffset + sub == data.size,
          )
        )
        remaining -= sub
        subOffset += sub
      }
    } else {
      var offset = continuousStreamMap[streamId] ?: 0L
      var remaining = data.size
      var subOffset = 0
      while (remaining > 0) {
        val sub = minOf(remaining, 1200)
        frameList.add(
          StreamFrame.of(
            streamId,
            offset,
            sub.toLong(),
            ArrayUtils.subarray(data, subOffset, subOffset + sub),
            false,
          )
        )
        remaining -= sub
        subOffset += sub
        offset += sub
      }
      continuousStreamMap[streamId] = offset
    }
  }

  @Synchronized
  fun get(): Frames {
    val f = Frames.of(frameList)
    frameList.clear()
    return f
  }
}
