package packetproxy.util

import java.util.function.Predicate

fun interface ThrowingPredicate<T> : Predicate<T> {
  override fun test(e: T): Boolean {
    try {
      return test0(e)
    } catch (ex: Throwable) {
      sneakyThrow(ex)
      throw IllegalStateException("Unreachable")
    }
  }

  @Throws(Throwable::class) fun test0(e: T): Boolean
}
