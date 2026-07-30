/*
 * Copyright 2026 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy

import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.annotations.TearDown
import org.openjdk.jmh.infra.Blackhole

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class ThreadModelBenchmark {
  @Param("1", "10", "50") var duplexCount = 0

  @Benchmark
  fun startAndJoinSixThreadsPerDuplex(bh: Blackhole) {
    val started = AtomicLong()
    val latch = CountDownLatch(duplexCount * 6)
    val threads =
      (0 until duplexCount).flatMap {
        (0 until 6).map {
          Thread {
            started.incrementAndGet()
            latch.countDown()
          }
        }
      }
    threads.forEach { it.start() }
    latch.await(5, TimeUnit.SECONDS)
    threads.forEach { it.join(1000) }
    bh.consume(started.get())
  }
}

@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class PipedHopBenchmark {
  @Param("1024", "16384", "65536") var chunkSize = 0

  private lateinit var payload: ByteArray
  private lateinit var pin: PipedInputStream
  private lateinit var pout: PipedOutputStream
  private lateinit var reader: Thread
  private val consumed = AtomicLong()

  @Setup
  fun setup() {
    payload = ByteArray(chunkSize) { (it % 251).toByte() }
    pin = PipedInputStream(65536)
    pout = PipedOutputStream(pin)
    reader = Thread {
      val buf = ByteArray(65536)
      try {
        while (true) {
          val n = pin.read(buf)
          if (n < 0) break
          consumed.addAndGet(n.toLong())
        }
      } catch (_: Exception) {}
    }
    reader.isDaemon = true
    reader.start()
  }

  @TearDown
  fun tearDown() {
    try {
      pout.close()
    } catch (_: Exception) {}
    try {
      pin.close()
    } catch (_: Exception) {}
    reader.join(1000)
  }

  @Benchmark
  fun writeFlushThroughPipe(bh: Blackhole) {
    pout.write(payload)
    pout.flush()
    bh.consume(consumed.get())
  }
}
