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
package packetproxy.perf

import com.sun.net.httpserver.HttpServer
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.URL
import java.nio.file.Files
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.system.exitProcess
import packetproxy.AppInitializer

/**
 * Headless E2E proxy throughput/latency measurement.
 *
 * Run: ./gradlew :app:measureE2E
 */
object E2EProxyMeasurement {
  @JvmStatic
  fun main(args: Array<String>) {
    val requests = argInt(args, "--requests", 200)
    val warmup = argInt(args, "--warmup", 20)
    val concurrency = argInt(args, "--concurrency", 1)
    val bodySize = argInt(args, "--body-bytes", 1024)

    val backend = startBackend(bodySize)
    val proxyPort = freePort()
    val dbPath = Files.createTempFile("pp-e2e-", ".sqlite3")
    Files.deleteIfExists(dbPath)
    val settingsPath = Files.createTempFile("pp-e2e-settings-", ".json")
    Files.writeString(
      settingsPath,
      """
      {
        "listenPorts": [{
          "id": 1,
          "enabled": true,
          "ca_name": "PacketProxy per-user CA",
          "port": $proxyPort,
          "type": "HTTP_PROXY",
          "server_id": 0
        }],
        "servers": [],
        "modifications": [],
        "sslPassThroughs": []
      }
      """
        .trimIndent(),
    )

    val app = AppInitializer.bootstrap()
    app.setArgs(true, settingsPath.toAbsolutePath().toString())
    app.initCore()
    app.createModelServices(dbPath.toAbsolutePath().toString(), false)
    app.initGulp()
    app.initComponents()

    waitUntilListening(proxyPort, 15_000)

    val targetUrl = "http://127.0.0.1:${backend.address.port}/bench"
    val proxy = java.net.Proxy(java.net.Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort))

    // Warmup
    repeat(warmup) { oneRequest(proxy, targetUrl) }

    val latenciesMs = DoubleArray(requests)
    val errors = AtomicInteger()
    val startNs = System.nanoTime()
    if (concurrency <= 1) {
      for (i in 0 until requests) {
        val t0 = System.nanoTime()
        try {
          oneRequest(proxy, targetUrl)
          latenciesMs[i] = (System.nanoTime() - t0) / 1_000_000.0
        } catch (e: Exception) {
          errors.incrementAndGet()
          latenciesMs[i] = Double.NaN
        }
      }
    } else {
      val pool = Executors.newFixedThreadPool(concurrency)
      val idx = AtomicInteger()
      val tasks =
        (0 until requests).map {
          pool.submit {
            val i = idx.getAndIncrement()
            val t0 = System.nanoTime()
            try {
              oneRequest(proxy, targetUrl)
              latenciesMs[i] = (System.nanoTime() - t0) / 1_000_000.0
            } catch (_: Exception) {
              errors.incrementAndGet()
              latenciesMs[i] = Double.NaN
            }
          }
        }
      tasks.forEach { it.get(60, TimeUnit.SECONDS) }
      pool.shutdownNow()
    }
    val elapsedSec = (System.nanoTime() - startNs) / 1_000_000_000.0
    val ok = latenciesMs.filter { !it.isNaN() }.sorted()
    val packetCount = app.requireModelServices().packets.countOf()

    val summary =
      mapOf(
        "requests" to requests,
        "warmup" to warmup,
        "concurrency" to concurrency,
        "body_bytes" to bodySize,
        "errors" to errors.get(),
        "elapsed_sec" to round(elapsedSec, 3),
        "rps" to round(ok.size / elapsedSec, 2),
        "latency_ms_p50" to percentile(ok, 0.50),
        "latency_ms_p90" to percentile(ok, 0.90),
        "latency_ms_p99" to percentile(ok, 0.99),
        "latency_ms_avg" to round(ok.average(), 3),
        "latency_ms_min" to round(ok.minOrNull() ?: 0.0, 3),
        "latency_ms_max" to round(ok.maxOrNull() ?: 0.0, 3),
        "packets_in_db" to packetCount,
        "proxy_port" to proxyPort,
        "backend_port" to backend.address.port,
      )

    println("E2E_PROXY_MEASUREMENT_JSON=" + toJson(summary))
    summary.forEach { (k, v) -> println("$k=$v") }

    backend.stop(0)
    exitProcess(0)
  }

  private fun startBackend(bodySize: Int): HttpServer {
    val body = ByteArray(bodySize) { ('x'.code).toByte() }
    val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    server.createContext("/bench") { exchange ->
      val responseHeaders = exchange.responseHeaders
      responseHeaders.add("Content-Type", "text/plain")
      exchange.sendResponseHeaders(200, body.size.toLong())
      exchange.responseBody.use { it.write(body) }
    }
    server.executor = Executors.newCachedThreadPool()
    server.start()
    return server
  }

  private fun oneRequest(proxy: java.net.Proxy, url: String) {
    val conn = URL(url).openConnection(proxy) as HttpURLConnection
    conn.connectTimeout = 5000
    conn.readTimeout = 10000
    conn.requestMethod = "GET"
    conn.setRequestProperty("Connection", "close")
    conn.inputStream.use { it.readBytes() }
    conn.disconnect()
  }

  private fun waitUntilListening(port: Int, timeoutMs: Long) {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
      try {
        ServerSocket().use { probe ->
          // If something is listening, connect succeeds via Socket — use ServerSocket bind check
          // inverted
        }
        java.net.Socket("127.0.0.1", port).use {
          return
        }
      } catch (_: Exception) {
        Thread.sleep(100)
      }
    }
    error("proxy did not start listening on $port within ${timeoutMs}ms")
  }

  private fun freePort(): Int = ServerSocket(0).use { it.localPort }

  private fun argInt(args: Array<String>, name: String, default: Int): Int {
    val raw = args.firstOrNull { it.startsWith("$name=") }?.substringAfter("=") ?: return default
    return raw.toInt()
  }

  private fun percentile(sorted: List<Double>, p: Double): Double {
    if (sorted.isEmpty()) return 0.0
    val idx = ((sorted.size - 1) * p).toInt().coerceIn(0, sorted.lastIndex)
    return round(sorted[idx], 3)
  }

  private fun round(v: Double, digits: Int): Double {
    var factor = 1.0
    repeat(digits) { factor *= 10 }
    return Math.round(v * factor) / factor
  }

  private fun toJson(map: Map<String, Any>): String =
    map.entries.joinToString(prefix = "{", postfix = "}") { (k, v) ->
      val value =
        when (v) {
          is String -> "\"$v\""
          else -> v.toString()
        }
      "\"$k\":$value"
    }
}
