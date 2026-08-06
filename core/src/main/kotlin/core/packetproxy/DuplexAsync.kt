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
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.Endpoint
import packetproxy.util.errWithStackTrace

class DuplexAsync
@Throws(Exception::class)
constructor(private val client: Endpoint, private val server: Endpoint) : Duplex() {
  private val client_to_server: Simplex
  private val server_to_client: Simplex
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
    // Socketが取れるendpointではSO_TIMEOUTベースの読み込みに切り替え、Simplex側の
    // newSingleThreadExecutor()生成を避ける（P2a）。
    client_to_server.setTimeoutSocket(client.getSocket())
    server_to_client.setTimeoutSocket(server.getSocket())

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
    if (useDedicatedFlowThreads) {
      startWithDedicatedFlowThreads()
    } else {
      // HTTP/2やHTTP/3のようなストリーム単位のフロー制御が不要なプロトコルでは、
      // client_to_server/server_to_clientのSimplexの出力を直接相手側のOutputStreamへ
      // つなぎ、flow control用の中継スレッドを4本立てるオーバーヘッドを避ける（P2c）。
      client_to_server.setOutputStream(server_output)
      server_to_client.setOutputStream(client_output)
    }

    client_to_server.start()
    server_to_client.start()
  }

  private fun startWithDedicatedFlowThreads() {
    IO_POOL.submit {
      try {
        val inputBuf = ByteArray(65536)
        var inputLen: Int
        while (flow_controlled_client_input.read(inputBuf).also { inputLen = it } > 0) {
          callOnClientChunkFlowControl(copyInputChunk(inputBuf, inputLen))
        }
        flow_controlled_client_input.close()
        closeOnClientChunkFlowControl()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    IO_POOL.submit {
      try {
        val inputBuf = ByteArray(65536)
        var inputLen: Int
        while (flow_controlled_server_input.read(inputBuf).also { inputLen = it } > 0) {
          callOnServerChunkFlowControl(copyInputChunk(inputBuf, inputLen))
        }
        flow_controlled_server_input.close()
        closeOnServerChunkFlowControl()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    IO_POOL.submit {
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
          errWithStackTrace(e1)
        }
        errWithStackTrace(e)
      }
    }

    IO_POOL.submit {
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
          errWithStackTrace(e1)
        }
        errWithStackTrace(e)
      }
    }
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

  private fun copyInputChunk(inputBuf: ByteArray, inputLen: Int): ByteArray {
    if (inputLen >= inputBuf.size) {
      return inputBuf.clone()
    }
    return ArrayUtils.subarray(inputBuf, 0, inputLen)
  }

  companion object {
    // 各コネクションごとにThreadを生成する代わりに、flow control用の中継タスクを
    // 共有のキャッシュ済みスレッドプールに委譲してスレッド生成コストを削減する（P2b）。
    private val IO_POOL: ExecutorService =
      Executors.newCachedThreadPool { r -> Thread(r, "pp-duplex-io").apply { isDaemon = true } }
  }
}
