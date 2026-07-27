package packetproxy.quic.service.framegenerator.helper

import java.io.ByteArrayOutputStream
import java.util.HashMap
import java.util.Optional
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId
import packetproxy.quic.value.frame.StreamFrame

class OneshotStream(private val streamId: StreamId) {
  private val frameMap = HashMap<Long, StreamFrame>()
  private var lastFrameReceived = false
  private var alreadyResultReturned = false
  private var totalLength = 0L

  fun put(frame: StreamFrame) {
    if (frame.finished) {
      lastFrameReceived = true
      totalLength = frame.offset + frame.length
    }
    frameMap[frame.offset] = frame
  }

  @Throws(Exception::class)
  fun get(): Optional<QuicMessage> {
    if (alreadyResultReturned || !lastFrameReceived) return Optional.empty()
    var offset = 0L
    val data = ByteArrayOutputStream()
    while (offset < totalLength) {
      val frame = frameMap[offset] ?: return Optional.empty()
      offset += frame.length
      data.write(frame.streamData)
    }
    alreadyResultReturned = true
    return Optional.of(QuicMessage.of(streamId, data.toByteArray()))
  }
}
