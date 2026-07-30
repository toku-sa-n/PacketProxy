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

import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Level
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.annotations.TearDown
import org.openjdk.jmh.infra.Blackhole
import packetproxy.model.CAs.PacketProxyCAPerUser

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class CertCacheBenchmark {
  private lateinit var cache: CertCacheManager
  private lateinit var ca: PacketProxyCAPerUser
  private var hostCounter = 0

  @Setup(Level.Iteration)
  fun setup() {
    cache = CertCacheManager()
    ca = PacketProxyCAPerUser()
    hostCounter = 0
  }

  @Benchmark
  fun getKeyStoreCold(bh: Blackhole) {
    hostCounter++
    val host = "bench-$hostCounter.example.com"
    bh.consume(cache.getKeyStore(host, arrayOf(host), ca))
  }

  @Benchmark
  fun getKeyStoreWarm(bh: Blackhole) {
    val host = "warm.example.com"
    bh.consume(cache.getKeyStore(host, arrayOf(host), ca))
  }
}

@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class TlsHandshakeBenchmark {
  private lateinit var serverSocket: SSLServerSocket
  private lateinit var clientContext: SSLContext
  private var port = 0

  @Setup(Level.Trial)
  fun setup() {
    val ca = PacketProxyCAPerUser()
    val cache = CertCacheManager()
    val host = "localhost"
    val ks = cache.getKeyStore(host, arrayOf(host, "127.0.0.1"), ca)
    val serverContext = sslContextFromKeyStore(ks)
    serverSocket = serverContext.serverSocketFactory.createServerSocket(0) as SSLServerSocket
    port = serverSocket.localPort
    clientContext = trustAllClientContext()
    Thread {
        while (!serverSocket.isClosed) {
          try {
            val sock = serverSocket.accept() as SSLSocket
            sock.startHandshake()
            sock.close()
          } catch (_: Exception) {
            break
          }
        }
      }
      .also {
        it.isDaemon = true
        it.start()
      }
  }

  @TearDown(Level.Trial)
  fun tearDown() {
    try {
      serverSocket.close()
    } catch (_: Exception) {}
  }

  @Benchmark
  fun clientHandshake(bh: Blackhole) {
    val socket = clientContext.socketFactory.createSocket() as SSLSocket
    socket.connect(InetSocketAddress("127.0.0.1", port), 3000)
    socket.soTimeout = 3000
    socket.startHandshake()
    bh.consume(socket.session.protocol)
    socket.close()
  }

  private fun sslContextFromKeyStore(ks: KeyStore): SSLContext {
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    kmf.init(ks, "testtest".toCharArray())
    val ctx = SSLContext.getInstance("TLS")
    ctx.init(kmf.keyManagers, null, SecureRandom())
    return ctx
  }

  private fun trustAllClientContext(): SSLContext {
    val trustAll =
      arrayOf<TrustManager>(
        object : X509TrustManager {
          override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

          override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}

          override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
      )
    val ctx = SSLContext.getInstance("TLS")
    ctx.init(null, trustAll, SecureRandom())
    return ctx
  }
}
