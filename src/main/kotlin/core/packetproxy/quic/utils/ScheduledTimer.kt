package packetproxy.quic.utils

import java.time.Duration
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

class ScheduledTimer(private val onTimeout: Runnable) {
  private val scheduler = Executors.newScheduledThreadPool(1)
  private var future: ScheduledFuture<*>? = null

  @Synchronized
  fun update(time: Instant) {
    if (time == Instant.MAX) cancel()
    else {
      val delay = Duration.between(Instant.now(), time).toMillis()
      future = scheduler.schedule(onTimeout, delay, TimeUnit.MILLISECONDS)
    }
  }

  @Synchronized
  fun cancel() {
    future?.cancel(false)
  }
}
