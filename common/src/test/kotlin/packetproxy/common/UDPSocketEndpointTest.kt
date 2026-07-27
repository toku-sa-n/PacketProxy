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

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.Arrays
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class UDPSocketEndpointTest {
  @Test
  fun testIgnorePacketFromUnexpectedSource() {
    openFixture().use { fixture ->
      val request = ascii("request")
      val response = ascii("server-response")
      val intruderPayload = ascii("intruder-payload")

      fixture.sendRequestFromEndpoint(request)
      val serverReceivedPacket = fixture.receiveFromEndpoint()
      assertArrayEquals(request, getPayload(serverReceivedPacket))

      val endpointResponse = fixture.readFromEndpointAsync()
      fixture.sendUnexpectedPacket(intruderPayload)
      assertReadTimeout(endpointResponse)

      fixture.sendResponseToEndpoint(response, serverReceivedPacket)
      assertArrayEquals(response, fixture.await(endpointResponse))
    }
  }

  private fun openFixture(): TestFixture {
    val existingThreads = HashSet(Thread.getAllStackTraces().keys)
    val serverSocket = DatagramSocket(InetSocketAddress("127.0.0.1", 0))
    serverSocket.soTimeout = 1000
    val intruderSocket = DatagramSocket(InetSocketAddress("127.0.0.1", 0))
    val endpoint = UDPSocketEndpoint(InetSocketAddress("127.0.0.1", serverSocket.localPort))
    val endpointThreads = getNewThreads(existingThreads)
    val executor = Executors.newSingleThreadExecutor()
    return TestFixture(serverSocket, intruderSocket, endpoint, endpointThreads, executor)
  }

  private fun ascii(value: String): ByteArray = value.toByteArray(StandardCharsets.US_ASCII)

  private fun getPayload(packet: DatagramPacket): ByteArray =
    Arrays.copyOf(packet.data, packet.length)

  private fun assertReadTimeout(future: Future<ByteArray>) {
    assertThrows(TimeoutException::class.java) { future.get(200, TimeUnit.MILLISECONDS) }
  }

  private fun getNewThreads(existingThreads: Set<Thread>): Set<Thread> {
    val currentThreads = Thread.getAllStackTraces().keys
    val newThreads = HashSet<Thread>()
    for (thread in currentThreads) {
      if (!existingThreads.contains(thread)) {
        newThreads.add(thread)
      }
    }
    return newThreads
  }

  private fun closeEndpoint(endpoint: UDPSocketEndpoint, endpointThreads: Set<Thread>) {
    getSocket(endpoint).close()

    val pipe = getPipe(endpoint)
    pipe.getRawEndpoint().getInputStream().close()
    pipe.getRawEndpoint().getOutputStream().close()
    pipe.getProxyRawEndpoint().getInputStream().close()
    pipe.getProxyRawEndpoint().getOutputStream().close()

    for (thread in endpointThreads) {
      thread.interrupt()
      thread.join(1000)
    }
  }

  private fun getSocket(endpoint: UDPSocketEndpoint): DatagramSocket {
    val socketField = UDPSocketEndpoint::class.java.getDeclaredField("socket")
    socketField.isAccessible = true
    return socketField.get(endpoint) as DatagramSocket
  }

  private fun getPipe(endpoint: UDPSocketEndpoint): PipeEndpoint {
    val pipeField = UDPSocketEndpoint::class.java.getDeclaredField("pipe")
    pipeField.isAccessible = true
    return pipeField.get(endpoint) as PipeEndpoint
  }

  private inner class TestFixture(
    private val serverSocket: DatagramSocket,
    private val intruderSocket: DatagramSocket,
    private val endpoint: UDPSocketEndpoint,
    private val endpointThreads: Set<Thread>,
    private val executor: ExecutorService,
  ) : AutoCloseable {
    private val bufferSize = 4096

    fun sendRequestFromEndpoint(payload: ByteArray) {
      val endpointOutput = endpoint.getOutputStream()
      endpointOutput.write(payload)
      endpointOutput.flush()
    }

    fun receiveFromEndpoint(): DatagramPacket {
      val packet = DatagramPacket(ByteArray(bufferSize), bufferSize)
      serverSocket.receive(packet)
      return packet
    }

    fun readFromEndpointAsync(): Future<ByteArray> =
      executor.submit<ByteArray> {
        val endpointInput = endpoint.getInputStream()
        val buffer = ByteArray(bufferSize)
        val length = endpointInput.read(buffer)
        Arrays.copyOf(buffer, length)
      }

    fun sendUnexpectedPacket(payload: ByteArray) {
      val packet =
        DatagramPacket(
          payload,
          payload.size,
          InetSocketAddress("127.0.0.1", endpoint.getLocalPort()),
        )
      intruderSocket.send(packet)
    }

    fun sendResponseToEndpoint(payload: ByteArray, requestPacket: DatagramPacket) {
      val responsePacket = DatagramPacket(payload, payload.size, requestPacket.socketAddress)
      serverSocket.send(responsePacket)
    }

    fun await(future: Future<ByteArray>): ByteArray = future.get(1, TimeUnit.SECONDS)

    override fun close() {
      executor.shutdownNow()
      closeEndpoint(endpoint, endpointThreads)
      intruderSocket.close()
      serverSocket.close()
    }
  }
}
