package packetproxy.util

import java.util.function.Function

fun interface ThrowingFunction<T, R> : Function<T, R> {
  override fun apply(t: T): R {
    try {
      return apply0(t)
    } catch (ex: Throwable) {
      sneakyThrow(ex)
      throw IllegalStateException("Unreachable")
    }
  }

  @Throws(Throwable::class) fun apply0(t: T): R
}
