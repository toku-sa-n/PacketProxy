package packetproxy.util

import java.util.function.Consumer

fun interface ThrowingConsumer<T> : Consumer<T> {
  override fun accept(e: T) {
    try {
      accept0(e)
    } catch (ex: Throwable) {
      sneakyThrow(ex)
    }
  }

  @Throws(Throwable::class) fun accept0(e: T)
}
