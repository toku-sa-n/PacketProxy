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
package packetproxy.encode

import java.net.InetSocketAddress
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
import packetproxy.model.Packet

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class EncodeHTTPBenchmark {
  @Param("1kb", "10kb", "100kb") lateinit var bodySize: String

  private lateinit var encoder: EncodeHTTP
  private lateinit var request: ByteArray
  private lateinit var response: ByteArray
  private lateinit var requestPacket: Packet
  private lateinit var responsePacket: Packet

  @Setup
  fun setup() {
    encoder = EncodeHTTP("http/1.1")
    val bodyBytes =
      when (bodySize) {
        "1kb" -> 1024
        "10kb" -> 10 * 1024
        else -> 100 * 1024
      }
    val body = ByteArray(bodyBytes) { ('a'.code + (it % 26)).toByte() }
    request =
      buildHttp(
        listOf(
          "GET /bench HTTP/1.1",
          "Host: example.com",
          "User-Agent: PacketProxy-JMH",
          "Content-Length: ${body.size}",
        ),
        body,
      )
    response =
      buildHttp(
        listOf(
          "HTTP/1.1 200 OK",
          "Content-Type: text/plain",
          "Content-Length: ${body.size}",
          "Connection: keep-alive",
        ),
        body,
      )
    requestPacket =
      Packet(
        8080,
        InetSocketAddress("127.0.0.1", 12345),
        InetSocketAddress("127.0.0.1", 443),
        "example.com",
        false,
        "HTTP",
        "http/1.1",
        Packet.Direction.CLIENT,
        1,
        1L,
      )
    requestPacket.setReceivedData(request)
    requestPacket.setDecodedData(request)
    requestPacket.setModifiedData(request)
    responsePacket =
      Packet(
        8080,
        InetSocketAddress("127.0.0.1", 12345),
        InetSocketAddress("127.0.0.1", 443),
        "example.com",
        false,
        "HTTP",
        "http/1.1",
        Packet.Direction.SERVER,
        1,
        1L,
      )
    responsePacket.setReceivedData(response)
    responsePacket.setDecodedData(response)
    responsePacket.setModifiedData(response)
  }

  @Benchmark
  fun checkDelimiter(bh: Blackhole) {
    bh.consume(encoder.checkDelimiter(request))
  }

  @Benchmark
  fun decodeEncodeClientRoundTrip(bh: Blackhole) {
    val decoded = encoder.decodeClientRequest(request)
    bh.consume(encoder.encodeClientRequest(decoded))
  }

  @Benchmark
  fun decodeEncodeServerRoundTrip(bh: Blackhole) {
    val decoded = encoder.decodeServerResponse(response)
    bh.consume(encoder.encodeServerResponse(decoded))
  }

  @Benchmark
  fun summarizedRequest(bh: Blackhole) {
    bh.consume(encoder.getSummarizedRequest(requestPacket))
  }

  @Benchmark
  fun summarizedResponse(bh: Blackhole) {
    bh.consume(encoder.getSummarizedResponse(responsePacket))
  }

  @Benchmark
  fun historyRowFields(bh: Blackhole) {
    // Swing なしで GUIHistory.makeRowDataFromPacket の主要コストを近似
    bh.consume(encoder.getSummarizedRequest(requestPacket))
    bh.consume(encoder.getSummarizedResponse(responsePacket))
    bh.consume(requestPacket.getDecodedData().size)
    bh.consume(responsePacket.getDecodedData().size)
  }

  private fun buildHttp(headers: List<String>, body: ByteArray): ByteArray {
    val header = (headers.joinToString("\r\n") + "\r\n\r\n").toByteArray(StandardCharsets.UTF_8)
    return header + body
  }
}
