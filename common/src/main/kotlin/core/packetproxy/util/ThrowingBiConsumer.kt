package packetproxy.util

import java.util.function.BiConsumer

fun interface ThrowingBiConsumer<T, R> : BiConsumer<T, R> {
  override fun accept(t: T, r: R) {
    try {
      accept0(t, r)
    } catch (ex: Throwable) {
      sneakyThrow(ex)
    }
  }

  @Throws(Throwable::class) fun accept0(t: T, r: R)
}
