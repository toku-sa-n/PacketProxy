package packetproxy.quic.service.framegenerator.helper

import java.io.ByteArrayOutputStream
import java.util.HashMap
import java.util.Optional
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId
import packetproxy.quic.value.frame.StreamFrame

class ContinuousStream(val streamId: StreamId) {
  private val frameMap = HashMap<Long, StreamFrame>()
  private var currentOffset = 0L

  fun put(frame: StreamFrame) {
    frameMap[frame.offset] = frame
  }

  @Throws(Exception::class)
  fun get(): Optional<QuicMessage> {
    val frame = frameMap[currentOffset] ?: return Optional.empty()
    val data = ByteArrayOutputStream()
    data.write(frame.streamData)
    currentOffset += frame.length
    while (frameMap[currentOffset] != null) {
      val extra = frameMap[currentOffset]!!
      data.write(extra.getBytes())
      currentOffset += extra.length
    }
    return Optional.of(QuicMessage.of(streamId, data.toByteArray()))
  }
}
