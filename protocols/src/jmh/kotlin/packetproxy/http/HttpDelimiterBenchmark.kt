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
package packetproxy.http

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream
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
open class HttpDelimiterBenchmark {
  @Param(
    "complete_plain",
    "incomplete_header",
    "complete_chunked",
    "gzip_complete",
    "gzip_incomplete",
  )
  lateinit var scenario: String

  private lateinit var data: ByteArray

  @Setup
  fun setup() {
    data =
      when (scenario) {
        "complete_plain" ->
          httpMessage(
            headers =
              listOf(
                "GET /index.html HTTP/1.1",
                "Host: example.com",
                "Content-Length: 11",
                "Connection: keep-alive",
              ),
            body = "hello world".toByteArray(),
          )
        "incomplete_header" ->
          "GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n"
            .toByteArray(StandardCharsets.UTF_8)
        "complete_chunked" ->
          httpMessage(
            headers =
              listOf("HTTP/1.1 200 OK", "Transfer-Encoding: chunked", "Content-Type: text/plain"),
            body = "5\r\nhello\r\n0\r\n\r\n".toByteArray(),
          )
        "gzip_complete" -> {
          val body = gzip("hello world repeated ".repeat(50).toByteArray())
          httpMessage(
            headers =
              listOf(
                "HTTP/1.1 200 OK",
                "Content-Encoding: gzip",
                "Content-Length: ${body.size}",
                "Content-Type: text/plain",
              ),
            body = body,
          )
        }
        "gzip_incomplete" -> {
          // Content-Length: 0 path triggers decompress-as-completeness-probe
          val body = gzip("hello world repeated ".repeat(50).toByteArray())
          val incomplete = body.copyOf(body.size / 2)
          httpMessage(
            headers =
              listOf("HTTP/1.1 200 OK", "Content-Encoding: gzip", "Content-Type: text/plain"),
            body = incomplete,
          )
        }
        else -> error("unknown scenario: $scenario")
      }
  }

  @Benchmark
  fun parseHttpDelimiter(bh: Blackhole) {
    bh.consume(Http.parseHttpDelimiter(data))
  }

  @Benchmark
  fun calcHeaderSize(bh: Blackhole) {
    bh.consume(HttpHeader.calcHeaderSize(data))
  }

  @Benchmark
  fun httpCreate(bh: Blackhole) {
    if (scenario == "incomplete_header" || scenario == "gzip_incomplete") {
      bh.consume(HttpHeader.calcHeaderSize(data))
      return
    }
    bh.consume(Http.create(data).getMethod())
  }

  private fun httpMessage(headers: List<String>, body: ByteArray): ByteArray {
    val headerBytes =
      (headers.joinToString("\r\n") + "\r\n\r\n").toByteArray(StandardCharsets.UTF_8)
    return headerBytes + body
  }

  private fun gzip(raw: ByteArray): ByteArray {
    val bout = ByteArrayOutputStream()
    GZIPOutputStream(bout).use { it.write(raw) }
    return bout.toByteArray()
  }
}
