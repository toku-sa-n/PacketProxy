package packetproxy.quic.value

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.function.Consumer
import java.util.function.Function
import java.util.function.Predicate
import java.util.stream.Collectors
import packetproxy.util.rethrow

class QuicMessages {
  private val messages = mutableListOf<QuicMessage>()

  private constructor()

  private constructor(msgs: List<QuicMessage>) {
    messages.addAll(msgs)
  }

  fun clear() = messages.clear()

  fun add(msg: QuicMessage) = messages.add(msg)

  fun addAll(msgs: QuicMessages) = messages.addAll(msgs.messages)

  operator fun get(index: Int) = messages[index]

  fun size() = messages.size

  fun forEach(action: Consumer<QuicMessage>) = messages.forEach(action)

  fun map(mapper: Function<QuicMessage, QuicMessage>) =
    of(messages.stream().map(mapper).collect(Collectors.toList()))

  fun filter(predicate: Predicate<QuicMessage>) =
    of(messages.stream().filter(predicate).collect(Collectors.toList()))

  fun getBytes(): ByteArray {
    val bytes = ByteArrayOutputStream()
    messages.forEach(rethrow { msg -> bytes.write(msg.getBytes()) })
    return bytes.toByteArray()
  }

  fun filter(streamId: StreamId) =
    QuicMessages(messages.stream().filter { it.streamIdIs(streamId) }.collect(Collectors.toList()))

  fun filterAllBut(streamId: StreamId) =
    QuicMessages(messages.stream().filter { !it.streamIdIs(streamId) }.collect(Collectors.toList()))

  override fun equals(other: Any?) =
    this === other || (other is QuicMessages && messages == other.messages)

  override fun hashCode() = messages.hashCode()

  override fun toString() = "QuicMessages(messages=$messages)"

  companion object {
    @JvmStatic fun emptyList() = QuicMessages()

    @JvmStatic fun of(msg: QuicMessage) = QuicMessages(listOf(msg))

    @JvmStatic fun of(msg1: QuicMessage, msg2: QuicMessage) = QuicMessages(listOf(msg1, msg2))

    @JvmStatic
    fun of(msg1: QuicMessage, msg2: QuicMessage, msg3: QuicMessage) =
      QuicMessages(listOf(msg1, msg2, msg3))

    @JvmStatic fun of(msgs: List<QuicMessage>) = QuicMessages(msgs)

    @JvmStatic fun parse(bytes: ByteArray) = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    fun parse(buffer: ByteBuffer): QuicMessages {
      val msgs = emptyList()
      while (buffer.remaining() > 16) {
        val savedPosition = buffer.position()
        val streamId = StreamId.parse(buffer)
        val dataLength = buffer.long
        if (buffer.remaining() < dataLength) {
          buffer.position(savedPosition)
          break
        }
        msgs.add(QuicMessage.of(streamId, SimpleBytes.parse(buffer, dataLength.toLong()).bytes))
      }
      return msgs
    }
  }
}
