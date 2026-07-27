/*
 * Copyright 2019 DeNA Co., Ltd.
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
package packetproxy.common

import java.util.Arrays
import java.util.Random
import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Level
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
open class StringSearchBenchmark {
  private lateinit var text: ByteArray
  private lateinit var pattern: ByteArray

  @Setup(Level.Iteration)
  fun beforeIteration() {
    val rng = Random()
    text = ByteArray(4 * 1024)
    rng.nextBytes(text)
    val x = rng.nextInt(4 * 1024 - 13)
    pattern = Arrays.copyOfRange(text, x, x + 12)
  }

  @Benchmark
  @BenchmarkMode(Mode.AverageTime)
  fun boyerMoore() {
    val alg = BoyerMoore(pattern)
    alg.searchIn(text)
  }

  @Benchmark
  @BenchmarkMode(Mode.AverageTime)
  fun bruteforceSearch() {
    Utils.indexOf(text, 0, text.size, pattern)
  }
}
