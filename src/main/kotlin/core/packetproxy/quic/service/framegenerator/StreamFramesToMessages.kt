package packetproxy.quic.service.framegenerator

import java.util.HashMap
import java.util.Optional
import packetproxy.quic.service.framegenerator.helper.ContinuousStream
import packetproxy.quic.service.framegenerator.helper.OneshotStream
import packetproxy.quic.value.QuicMessage
import packetproxy.quic.value.StreamId
import packetproxy.quic.value.frame.StreamFrame

class StreamFramesToMessages {
  private val continuousStreamMap = HashMap<StreamId, ContinuousStream>()
  private val oneshotStreamMap = HashMap<StreamId, OneshotStream>()

  fun put(frame: StreamFrame) =
    if (frame.streamId.isBidirectional()) putOneshot(frame) else putContinuous(frame)

  private fun putContinuous(frame: StreamFrame) {
    val id = frame.streamId
    if (!continuousStreamMap.containsKey(id)) continuousStreamMap[id] = ContinuousStream(id)
    continuousStreamMap[id]!!.put(frame)
  }

  private fun putOneshot(frame: StreamFrame) {
    val id = frame.streamId
    if (!oneshotStreamMap.containsKey(id)) oneshotStreamMap[id] = OneshotStream(id)
    oneshotStreamMap[id]!!.put(frame)
  }

  fun get(streamId: StreamId): Optional<QuicMessage> =
    if (streamId.isBidirectional()) oneshotStreamMap[streamId]?.get() ?: Optional.empty()
    else continuousStreamMap[streamId]?.get() ?: Optional.empty()
}
