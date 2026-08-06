@file:JvmName("Throwing")

package packetproxy.util

import java.util.function.Consumer
import java.util.function.Function
import java.util.function.Predicate
import javax.annotation.Nonnull

@Nonnull fun <T> rethrow(@Nonnull consumer: ThrowingConsumer<T>): Consumer<T> = consumer

@Nonnull fun <T> rethrowP(@Nonnull predicate: ThrowingPredicate<T>): Predicate<T> = predicate

@Nonnull fun <T, R> rethrowF(@Nonnull function: ThrowingFunction<T, R>): Function<T, R> = function

fun sneakyThrow(@Nonnull ex: Throwable): Unit {
  throw ex
}
