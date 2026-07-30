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
package packetproxy.common

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.infra.Blackhole

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class CryptBenchmark {
  @Param("1024", "102400", "1048576") var size = 0

  private lateinit var payload: ByteArray

  @Setup
  fun setup() {
    payload = ByteArray(size) { (it % 251).toByte() }
  }

  @Benchmark
  fun sha1(bh: Blackhole) {
    bh.consume(CryptUtils.sha1(payload))
  }

  @Benchmark
  fun sha1Twice(bh: Blackhole) {
    bh.consume(CryptUtils.sha1(payload))
    bh.consume(CryptUtils.sha1(payload))
  }

  @Benchmark
  fun sha256(bh: Blackhole) {
    bh.consume(CryptUtils.sha256(payload))
  }
}

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class BufferCopyBenchmark {
  @Param("8192", "65536") var size = 0

  @Param("0.5") var acceptRatio = 0.0

  private lateinit var bout: ByteArrayOutputStream
  private var acceptedSize = 0

  @Setup
  fun setup() {
    bout = ByteArrayOutputStream(size)
    bout.write(ByteArray(size) { (it % 251).toByte() })
    acceptedSize = (size * acceptRatio).toInt().coerceAtLeast(1)
  }

  @Benchmark
  fun simplexStyleReassembly(bh: Blackhole) {
    val currentBuffer = bout.toByteArray()
    val accepted = currentBuffer.copyOfRange(0, acceptedSize)
    val unaccepted = currentBuffer.copyOfRange(acceptedSize, currentBuffer.size)
    bout.reset()
    bout.write(unaccepted)
    bh.consume(accepted)
    bh.consume(unaccepted)
    // restore for next iteration
    bout.reset()
    bout.write(currentBuffer)
  }

  @Benchmark
  fun toByteArrayOnly(bh: Blackhole) {
    bh.consume(bout.toByteArray())
  }

  @Benchmark
  fun cloneFullBuffer(bh: Blackhole) {
    val buf = ByteArray(size) { (it % 251).toByte() }
    bh.consume(buf.clone())
  }
}

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class Utf8HeaderBenchmark {
  @Param("256", "1024", "4096", "16384") var headerBytes = 0

  private lateinit var header: ByteArray

  @Setup
  fun setup() {
    val line = "GET /api/v1/items?q=benchmark HTTP/1.1\r\nHost: example.com\r\n"
    val builder = StringBuilder()
    while (builder.length < headerBytes) {
      builder.append(line)
    }
    builder.append("\r\n")
    header = builder.toString().toByteArray(StandardCharsets.UTF_8)
  }

  @Benchmark
  fun utf8Decode(bh: Blackhole) {
    bh.consume(String(header, StandardCharsets.UTF_8))
  }

  @Benchmark
  fun utf8DecodePlusRegex(bh: Blackhole) {
    val headerStr = String(header, StandardCharsets.UTF_8)
    bh.consume(CONTENT_LENGTH.matcher(headerStr).find())
    bh.consume(CHUNKED.matcher(headerStr).find())
    bh.consume(GZIP.matcher(headerStr).find())
  }

  companion object {
    private val CONTENT_LENGTH =
      java.util.regex.Pattern.compile(
        "Content-Length: *([0-9]+)",
        java.util.regex.Pattern.CASE_INSENSITIVE,
      )
    private val CHUNKED =
      java.util.regex.Pattern.compile(
        "Transfer-Encoding: *chunked",
        java.util.regex.Pattern.CASE_INSENSITIVE,
      )
    private val GZIP =
      java.util.regex.Pattern.compile(
        "Content-Encoding: *gzip",
        java.util.regex.Pattern.CASE_INSENSITIVE,
      )
  }
}
