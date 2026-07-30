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

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.EventListener
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.net.ssl.SSLException
import javax.swing.event.EventListenerList
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

internal open class Simplex
@Throws(Exception::class)
constructor(private var `in`: InputStream?, private var out: OutputStream?) : Thread() {
  private val TIMEOUT = 30 * 1000
  private var flag_enable_event = false
  private var flag_break_loop = false
  private var flag_close = true
  private val input_data: ByteArray = ByteArray(100 * 1024)
  private var timeoutSocket: Socket? = null

  // タイムアウト管理にSocket#setSoTimeout()が使える場合(通常のSocketEndpoint/SSLSocketEndpoint)は、
  // newSingleThreadExecutor()によるスレッド生成コストを避けるためこちらを設定する。
  // Pipe由来のストリームなどSocketが無い場合はnullのままでExecutor/Future方式にフォールバックする。
  fun setTimeoutSocket(socket: Socket?) {
    timeoutSocket = socket
  }

  protected var simplexEventListenerList = EventListenerList()

  interface SimplexEventListener : EventListener {
    @Throws(Exception::class) fun onChunkArrived(data: ByteArray)

    @Throws(Exception::class) fun onChunkPassThrough(): ByteArray?

    @Throws(Exception::class) fun onChunkAvailable(): ByteArray?

    @Throws(Exception::class) fun onPacketReceived(data: ByteArray): Int

    @Throws(Exception::class) fun onChunkReceived(data: ByteArray): ByteArray?

    @Throws(Exception::class) fun onChunkSend(data: ByteArray): ByteArray?
  }

  abstract class SimplexEventAdapter : SimplexEventListener {
    var inputData = ByteArrayOutputStream()

    @Throws(Exception::class)
    override fun onChunkArrived(data: ByteArray) {
      inputData.write(data)
    }

    @Throws(Exception::class) override fun onChunkPassThrough(): ByteArray? = null

    @Throws(Exception::class)
    override fun onChunkAvailable(): ByteArray {
      val ret = inputData.toByteArray()
      inputData.reset()
      return ret
    }

    @Throws(Exception::class) override fun onPacketReceived(data: ByteArray): Int = data.size

    @Throws(Exception::class) override fun onChunkReceived(data: ByteArray): ByteArray = data

    @Throws(Exception::class) override fun onChunkSend(data: ByteArray): ByteArray = data
  }

  init {
    enableSimplexEvent()
  }

  fun disableSimplexEvent() {
    flag_enable_event = false
  }

  fun enableSimplexEvent() {
    flag_enable_event = true
  }

  fun isEnabledSimplexEvent(): Boolean = flag_enable_event

  fun addSimplexEventListener(listener: SimplexEventListener) {
    simplexEventListenerList.add(SimplexEventListener::class.java, listener)
  }

  @Throws(Exception::class)
  fun callOnPacketReceived(data: ByteArray): Int {
    if (!isEnabledSimplexEvent()) return data.size
    for (listener in simplexEventListenerList.getListeners(SimplexEventListener::class.java)) {
      return listener.onPacketReceived(data)
    }
    return data.size
  }

  @Throws(Exception::class)
  fun callOnChunkArrived(data: ByteArray) {
    if (!isEnabledSimplexEvent()) return
    for (listener in simplexEventListenerList.getListeners(SimplexEventListener::class.java)) {
      listener.onChunkArrived(data)
    }
  }

  @Throws(Exception::class)
  fun callOnChunkPassThrough(): ByteArray? {
    if (!isEnabledSimplexEvent()) return null
    for (listener in simplexEventListenerList.getListeners(SimplexEventListener::class.java)) {
      return listener.onChunkPassThrough()
    }
    return null
  }

  @Throws(Exception::class)
  fun callOnChunkAvailable(): ByteArray? {
    if (!isEnabledSimplexEvent()) return null
    for (listener in simplexEventListenerList.getListeners(SimplexEventListener::class.java)) {
      return listener.onChunkAvailable()
    }
    return null
  }

  @Throws(Exception::class)
  fun callOnChunkReceived(data: ByteArray): ByteArray? {
    if (!isEnabledSimplexEvent()) return data
    for (listener in simplexEventListenerList.getListeners(SimplexEventListener::class.java)) {
      return listener.onChunkReceived(data)
    }
    return data
  }

  @Throws(Exception::class)
  fun callOnChunkSend(data: ByteArray): ByteArray? {
    if (!isEnabledSimplexEvent()) return data
    for (listener in simplexEventListenerList.getListeners(SimplexEventListener::class.java)) {
      return listener.onChunkSend(data)
    }
    return data
  }

  override fun run() {
    if (`in` == null) return
    val socket = timeoutSocket
    if (socket != null) {
      runWithSocketTimeout(socket)
    } else {
      runWithExecutorTimeout()
    }
  }

  // Socketが利用できる場合、Socket#setSoTimeout()で読み込みタイムアウトを制御する。
  // newSingleThreadExecutor()によるスレッド生成/Future#get()のオーバーヘッドを避けられる。
  private fun runWithSocketTimeout(socket: Socket) {
    val bout = ByteArrayOutputStream()
    try {
      while (!flag_break_loop) {
        socket.soTimeout = if (bout.size() > 0) TIMEOUT else 0
        var length: Int
        try {
          length = `in`!!.read(input_data)
        } catch (e: SSLException) {
          length = -1
        } catch (e: SocketException) {
          length = -1
        }
        if (length == -1) break

        bout.write(input_data, 0, length)
        processAvailableChunks(bout)
      }
    } catch (e: SocketTimeoutException) {
      errWithStackTrace(e)
      log("-----")
      log(String(bout.toByteArray()))
      log("-----")
      try {
        `in`!!.close()
      } catch (e1: Exception) {
        errWithStackTrace(e)
      }
    } catch (e: SSLException) {
      // ignore
    } catch (e: SocketException) {
      // ignore
    } catch (e: Exception) {
      errWithStackTrace(e)
    } finally {
      closeStreamsIfNeeded()
    }
  }

  // Socketを持たないpipe由来のストリーム等では、従来通りExecutor + Future#get()でタイムアウトを実現する。
  private fun runWithExecutorTimeout() {
    val bout = ByteArrayOutputStream()
    val executor = Executors.newSingleThreadExecutor()
    val readTask = Callable {
      var ret: Int
      try {
        ret = `in`!!.read(input_data)
      } catch (e: SSLException) {
        ret = -1
      } catch (e: SocketException) {
        ret = -1
      }
      ret
    }

    try {
      while (!flag_break_loop) {
        val future = executor.submit(readTask)
        val timeout = if (bout.size() > 0) TIMEOUT else 24 * 60 * 60 * 1000
        val length = future.get(timeout.toLong(), TimeUnit.MILLISECONDS)
        if (length == -1) break

        bout.write(input_data, 0, length)
        processAvailableChunks(bout)
      }
    } catch (e: TimeoutException) {
      errWithStackTrace(e)
      log("-----")
      log(String(bout.toByteArray()))
      log("-----")
      try {
        `in`!!.close()
      } catch (e1: Exception) {
        errWithStackTrace(e)
      }
    } catch (e: SSLException) {
      // ignore
    } catch (e: SocketException) {
      // ignore
    } catch (e: Exception) {
      errWithStackTrace(e)
    } finally {
      executor.shutdownNow()
      closeStreamsIfNeeded()
    }
  }

  private fun processAvailableChunks(bout: ByteArrayOutputStream) {
    while (bout.size() > 0) {
      val currentBuffer = bout.toByteArray()
      val accepted_input_size = callOnPacketReceived(currentBuffer)
      if (accepted_input_size < 0 || accepted_input_size > currentBuffer.size) break
      val accepted_array = currentBuffer.copyOfRange(0, accepted_input_size)
      val unaccepted_array = currentBuffer.copyOfRange(accepted_input_size, currentBuffer.size)
      bout.reset()
      bout.write(unaccepted_array)

      callOnChunkArrived(accepted_array)

      var pass_through_data = callOnChunkPassThrough()
      while (pass_through_data != null && pass_through_data.isNotEmpty()) {
        out!!.write(pass_through_data)
        out!!.flush()
        pass_through_data = callOnChunkPassThrough()
      }

      var available_data = callOnChunkAvailable()
      while (available_data != null && available_data.isNotEmpty()) {
        val send_data = callOnChunkReceived(available_data)
        if (send_data != null && send_data.isNotEmpty()) {
          send(send_data)
        }
        available_data = callOnChunkAvailable()
      }
    }
  }

  private fun closeStreamsIfNeeded() {
    if (flag_close) {
      try {
        `in`?.close()
        out?.close()
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
      try {
        out?.close()
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }
  }

  @Throws(Exception::class)
  fun send(input_data: ByteArray?) {
    var data = input_data
    data = callOnChunkSend(data!!)
    if (out != null && data != null) {
      out!!.write(data)
      out!!.flush()
    }
  }

  @Throws(Exception::class)
  fun sendWithoutRecording(input_data: ByteArray) {
    if (out != null) {
      out!!.write(input_data)
      out!!.flush()
    }
  }

  fun setInputStream(input: InputStream?) {
    `in` = input
  }

  fun setOutputStream(output: OutputStream?) {
    out = output
  }

  fun setStreams(`in`: InputStream?, out: OutputStream?) {
    this.`in` = `in`
    this.out = out
  }

  @Throws(Exception::class)
  fun forceClose() {
    flag_break_loop = true
    flag_close = true
    `in`!!.close()
    out!!.close()
  }

  fun finishWithoutClose() {
    flag_break_loop = true
    flag_close = false
  }

  fun close() {
    flag_break_loop = true
    flag_close = true
  }
}
