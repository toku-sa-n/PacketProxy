package packetproxy.quic.service.connection.helper

import java.util.ArrayList
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.function.Predicate

class AwaitingPackets<T> {
  private val awaitings = ConcurrentLinkedDeque<T>()

  @Synchronized
  fun put(packets: List<T>) {
    awaitings.addAll(packets)
  }

  @Synchronized
  fun put(packet: T) {
    awaitings.offer(packet)
  }

  @Synchronized fun get(): T? = awaitings.poll()

  @Synchronized
  fun forEachAndRemovedIfReturnTrue(predicate: Predicate<T>) {
    val targets = ArrayList<T>()
    var e: T?
    while (awaitings.poll().also { e = it } != null) targets.add(e!!)
    val failed = ArrayList<T>()
    targets.forEach { if (!predicate.test(it)) failed.add(it) }
    if (failed.isNotEmpty()) awaitings.addAll(failed)
  }
}
