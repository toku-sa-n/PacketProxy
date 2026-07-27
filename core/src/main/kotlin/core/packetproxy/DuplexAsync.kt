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
package packetproxy

import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.Endpoint

class DuplexAsync
@Throws(Exception::class)
constructor(private val client: Endpoint, private val server: Endpoint) : Duplex() {
  private val client_to_server: Simplex
  private val server_to_client: Simplex
  private var clientFlowSourceThread: Thread? = null
  private var serverFlowSourceThread: Thread? = null
  private var clientFlowSinkThread: Thread? = null
  private var serverFlowSinkThread: Thread? = null
  private val client_input: InputStream? = client.getInputStream()
  private val server_input: InputStream? = server.getInputStream()
  private val client_output: OutputStream? = client.getOutputStream()
  private val server_output: OutputStream? = server.getOutputStream()
  private val flow_controlled_client_input: PipedInputStream
  private val flow_controlled_client_output: PipedOutputStream
  private val flow_controlled_server_input: PipedInputStream
  private val flow_controlled_server_output: PipedOutputStream

  init {
    flow_controlled_client_output = PipedOutputStream()
    flow_controlled_client_input = PipedInputStream(flow_controlled_client_output, 65536)

    flow_controlled_server_output = PipedOutputStream()
    flow_controlled_server_input = PipedInputStream(flow_controlled_server_output, 65536)

    client_to_server = createClientToServerSimplex(client_input, flow_controlled_server_output)
    server_to_client = createServerToClientSimplex(server_input, flow_controlled_client_output)

    disableDuplexEventListener()
  }

  override fun isListenPort(listenPort: Int): Boolean = client.getLocalPort() == listenPort

  @Throws(Exception::class)
  override fun createSameConnectionDuplex(): Duplex = DuplexAsync(client, server)

  @Throws(Exception::class)
  override fun prepareFastSend(data: ByteArray): ByteArray? {
    val accepted_length = callOnClientPacketReceived(data)
    if (accepted_length <= 0) {
      return null
    }
    val accepted = ArrayUtils.subarray(data, 0, accepted_length)
    val decoded = callOnClientChunkReceived(accepted)
    val encoded = callOnClientChunkSend(decoded!!)
    return encoded
  }

  @Throws(Exception::class)
  override fun execFastSend(data: ByteArray) {
    client_to_server.sendWithoutRecording(data)
  }

  @Throws(Exception::class)
  fun start() {
    clientFlowSourceThread = Thread {
      try {
        val inputBuf = ByteArray(65536)
        var inputLen: Int
        while (flow_controlled_client_input.read(inputBuf).also { inputLen = it } > 0) {
          callOnClientChunkFlowControl(ArrayUtils.subarray(inputBuf, 0, inputLen))
        }
        flow_controlled_client_input.close()
        closeOnClientChunkFlowControl()
      } catch (e: Exception) {
        // errWithStackTrace(e);
      }
    }

    serverFlowSourceThread = Thread {
      try {
        val inputBuf = ByteArray(65536)
        var inputLen: Int
        while (flow_controlled_server_input.read(inputBuf).also { inputLen = it } > 0) {
          callOnServerChunkFlowControl(ArrayUtils.subarray(inputBuf, 0, inputLen))
        }
        flow_controlled_server_input.close()
        closeOnServerChunkFlowControl()
      } catch (e: Exception) {
        // errWithStackTrace(e);
      }
    }

    clientFlowSinkThread = Thread {
      try {
        val inputBuf = ByteArray(65536)
        var inputLen: Int
        while (getClientChunkFlowControlSink().read(inputBuf).also { inputLen = it } > 0) {
          client_output!!.write(inputBuf, 0, inputLen)
          client_output.flush()
        }
        flow_controlled_client_input.close()
        client_output!!.close()
      } catch (e: Exception) {
        try {
          flow_controlled_client_input.close()
          client_output!!.close()
        } catch (e1: Exception) {
          // errWithStackTrace(e1);
        }
        // errWithStackTrace(e);
      }
    }

    serverFlowSinkThread = Thread {
      try {
        val inputBuf = ByteArray(65536)
        var inputLen: Int
        while (getServerChunkFlowControlSink().read(inputBuf).also { inputLen = it } > 0) {
          server_output!!.write(inputBuf, 0, inputLen)
          server_output.flush()
        }
        flow_controlled_server_input.close()
        server_output!!.close()
      } catch (e: Exception) {
        try {
          flow_controlled_server_input.close()
          server_output!!.close()
        } catch (e1: Exception) {
          // errWithStackTrace(e1);
        }
        // errWithStackTrace(e);
      }
    }

    client_to_server.start()
    server_to_client.start()
    clientFlowSinkThread!!.start()
    serverFlowSinkThread!!.start()
    clientFlowSourceThread!!.start()
    serverFlowSourceThread!!.start()
  }

  @Throws(Exception::class)
  override fun close() {
    client_to_server.close()
    server_to_client.close()
    client_input!!.close()
    server_output!!.close()
    server_input!!.close()
    client_output!!.close()
  }

  @Throws(Exception::class)
  private fun createClientToServerSimplex(`in`: InputStream?, out: OutputStream): Simplex {
    val simplex = Simplex(`in`, out)
    simplex.addSimplexEventListener(
      object : Simplex.SimplexEventListener {
        @Throws(Exception::class)
        override fun onChunkArrived(data: ByteArray) {
          callOnClientChunkArrived(data)
        }

        @Throws(Exception::class)
        override fun onChunkPassThrough(): ByteArray? = callOnClientChunkPassThrough()

        @Throws(Exception::class)
        override fun onChunkAvailable(): ByteArray? = callOnClientChunkAvailable()

        @Throws(Exception::class)
        override fun onChunkReceived(data: ByteArray): ByteArray? = callOnClientChunkReceived(data)

        @Throws(Exception::class)
        override fun onPacketReceived(data: ByteArray): Int = callOnClientPacketReceived(data)

        @Throws(Exception::class)
        override fun onChunkSend(data: ByteArray): ByteArray? = callOnClientChunkSend(data)
      }
    )
    return simplex
  }

  @Throws(Exception::class)
  private fun createServerToClientSimplex(`in`: InputStream?, out: OutputStream): Simplex {
    val simplex = Simplex(`in`, out)
    simplex.addSimplexEventListener(
      object : Simplex.SimplexEventListener {
        @Throws(Exception::class)
        override fun onChunkReceived(data: ByteArray): ByteArray? = callOnServerChunkReceived(data)

        @Throws(Exception::class)
        override fun onChunkArrived(data: ByteArray) {
          callOnServerChunkArrived(data)
        }

        @Throws(Exception::class)
        override fun onChunkPassThrough(): ByteArray? = callOnServerChunkPassThrough()

        @Throws(Exception::class)
        override fun onChunkAvailable(): ByteArray? = callOnServerChunkAvailable()

        @Throws(Exception::class)
        override fun onPacketReceived(data: ByteArray): Int = callOnServerPacketReceived(data)

        @Throws(Exception::class)
        override fun onChunkSend(data: ByteArray): ByteArray? = callOnServerChunkSend(data)
      }
    )
    return simplex
  }

  @Throws(Exception::class)
  override fun sendToClientImpl(data: ByteArray) {
    server_to_client.sendWithoutRecording(data)
  }

  @Throws(Exception::class)
  override fun sendToServerImpl(data: ByteArray) {
    client_to_server.sendWithoutRecording(data)
  }
}
