package packetproxy.util

import java.util.concurrent.atomic.AtomicInteger
import java.util.function.Consumer
import javax.annotation.Nonnull

@Nonnull
fun <T> withCounter(@Nonnull consumer: ThrowingBiConsumer<Int, T>): Consumer<T> {
  var counter = AtomicInteger(0)
  return Consumer { item -> consumer.accept(counter.getAndIncrement(), item) }
}
