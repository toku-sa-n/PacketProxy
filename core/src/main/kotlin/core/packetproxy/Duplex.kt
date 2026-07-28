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
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.EventListener
import javax.swing.event.EventListenerList
import packetproxy.util.errWithStackTrace

abstract class Duplex {
  protected var duplexEventListenerList = EventListenerList()
  private var flagEventListener = false
  private val pipeSize = 65536
  private var clientOutputForFlowControl: PipedOutputStream? = null
  private var clientInputForFlowControl: PipedInputStream? = null
  private var serverOutputForFlowControl: PipedOutputStream? = null
  private var serverInputForFlowControl: PipedInputStream? = null
  private var inputClientData = ByteArrayOutputStream()
  private var inputServerData = ByteArrayOutputStream()

  init {
    try {
      clientOutputForFlowControl = PipedOutputStream()
      clientInputForFlowControl = PipedInputStream(clientOutputForFlowControl, pipeSize)
      serverOutputForFlowControl = PipedOutputStream()
      serverInputForFlowControl = PipedInputStream(serverOutputForFlowControl, pipeSize)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  open fun disableDuplexEventListener() {
    flagEventListener = false
  }

  @Throws(Exception::class)
  open fun enableDuplexEventListener() {
    flagEventListener = true
  }

  @Throws(Exception::class)
  internal open fun isEnabledDuplexEventListener(): Boolean = flagEventListener

  @Throws(Exception::class)
  open fun addDuplexEventListener(listener: DuplexEventListener) {
    duplexEventListenerList.add(DuplexEventListener::class.java, listener)
    enableDuplexEventListener()
  }

  @Throws(Exception::class)
  open fun callOnClientPacketReceived(data: ByteArray): Int {
    if (!isEnabledDuplexEventListener()) return data.size

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onClientPacketReceived(data)
    }
    return data.size
  }

  @Throws(Exception::class)
  open fun callOnServerPacketReceived(data: ByteArray): Int {
    if (!isEnabledDuplexEventListener()) return data.size

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onServerPacketReceived(data)
    }
    return data.size
  }

  @Throws(Exception::class)
  open fun callOnClientChunkArrived(data: ByteArray) {
    if (!isEnabledDuplexEventListener()) inputClientData.write(data)

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      listener.onClientChunkArrived(data)
    }
  }

  @Throws(Exception::class)
  open fun callOnServerChunkArrived(data: ByteArray) {
    if (!isEnabledDuplexEventListener()) inputServerData.write(data)

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      listener.onServerChunkArrived(data)
    }
  }

  @Throws(Exception::class)
  open fun callOnClientChunkPassThrough(): ByteArray? {
    if (!isEnabledDuplexEventListener()) return null

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onClientChunkPassThrough()
    }
    return null
  }

  @Throws(Exception::class)
  open fun callOnServerChunkPassThrough(): ByteArray? {
    if (!isEnabledDuplexEventListener()) return null

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onServerChunkPassThrough()
    }
    return null
  }

  @Throws(Exception::class)
  open fun callOnClientChunkAvailable(): ByteArray? {
    if (!isEnabledDuplexEventListener()) {
      val result = inputClientData.toByteArray()
      inputClientData.reset()
      return result
    }

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onClientChunkAvailable()
    }
    return null
  }

  @Throws(Exception::class)
  open fun callOnServerChunkAvailable(): ByteArray? {
    if (!isEnabledDuplexEventListener()) {
      val result = inputServerData.toByteArray()
      inputServerData.reset()
      return result
    }

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onServerChunkAvailable()
    }
    return null
  }

  @Throws(Exception::class)
  open fun callOnClientChunkReceived(data: ByteArray): ByteArray? {
    if (!isEnabledDuplexEventListener()) return data

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onClientChunkReceived(data)
    }
    return data
  }

  @Throws(Exception::class)
  open fun callOnServerChunkReceived(data: ByteArray): ByteArray? {
    if (!isEnabledDuplexEventListener()) return data

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onServerChunkReceived(data)
    }
    return data
  }

  @Throws(Exception::class)
  open fun callOnClientChunkSend(data: ByteArray): ByteArray? {
    if (!isEnabledDuplexEventListener()) return data

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onClientChunkSend(data)
    }
    return data
  }

  @Throws(Exception::class)
  open fun callOnServerChunkSend(data: ByteArray): ByteArray? {
    if (!isEnabledDuplexEventListener()) return data

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onServerChunkSend(data)
    }
    return data
  }

  @Throws(Exception::class)
  open fun callOnClientChunkSendForced(data: ByteArray): ByteArray? {
    if (!isEnabledDuplexEventListener()) return data

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onClientChunkSendForced(data)
    }
    return data
  }

  @Throws(Exception::class)
  open fun callOnServerChunkSendForced(data: ByteArray): ByteArray? {
    if (!isEnabledDuplexEventListener()) return data

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.onServerChunkSendForced(data)
    }
    return data
  }

  @Throws(Exception::class)
  open fun callOnClientChunkFlowControl(data: ByteArray) {
    if (!isEnabledDuplexEventListener()) {
      clientOutputForFlowControl!!.write(data)
      clientOutputForFlowControl!!.flush()
    }

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      listener.onClientChunkFlowControl(data)
    }
  }

  @Throws(Exception::class)
  open fun closeOnClientChunkFlowControl() {
    if (!isEnabledDuplexEventListener()) clientOutputForFlowControl!!.close()

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      listener.closeClientChunkFlowControl()
    }
  }

  @Throws(Exception::class)
  open fun getClientChunkFlowControlSink(): InputStream {
    if (!isEnabledDuplexEventListener()) return clientInputForFlowControl!!

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.getClientChunkFlowControlSink()
    }
    return clientInputForFlowControl!!
  }

  @Throws(Exception::class)
  open fun callOnServerChunkFlowControl(data: ByteArray) {
    if (!isEnabledDuplexEventListener()) {
      serverOutputForFlowControl!!.write(data)
      serverOutputForFlowControl!!.flush()
    }

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      listener.onServerChunkFlowControl(data)
    }
  }

  @Throws(Exception::class)
  open fun closeOnServerChunkFlowControl() {
    if (!isEnabledDuplexEventListener()) serverOutputForFlowControl!!.close()

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      listener.closeServerChunkFlowControl()
    }
  }

  @Throws(Exception::class)
  open fun getServerChunkFlowControlSink(): InputStream {
    if (!isEnabledDuplexEventListener()) return serverInputForFlowControl!!

    for (listener in duplexEventListenerList.getListeners(DuplexEventListener::class.java)) {
      return listener.getServerChunkFlowControlSink()
    }
    return serverInputForFlowControl!!
  }

  @Throws(Exception::class) open fun send(data: ByteArray) {}

  @Throws(Exception::class) open fun encode(data: ByteArray) {}

  @Throws(Exception::class) open fun receive(): ByteArray? = null

  @Throws(Exception::class) open fun receiveAll() {}

  @Throws(Exception::class)
  open fun sendToClient(data: ByteArray) {
    sendToClientImpl(callOnServerChunkSendForced(data)!!)
  }

  @Throws(Exception::class)
  open fun sendToServer(data: ByteArray) {
    sendToServerImpl(callOnClientChunkSendForced(data)!!)
  }

  @Throws(Exception::class) protected open fun sendToClientImpl(data: ByteArray) {}

  @Throws(Exception::class) protected open fun sendToServerImpl(data: ByteArray) {}

  @Throws(Exception::class) open fun close() {}

  @Throws(Exception::class) open fun createSameConnectionDuplex(): Duplex? = null

  @Throws(Exception::class) open fun prepareFastSend(data: ByteArray): ByteArray? = null

  @Throws(Exception::class) open fun execFastSend(data: ByteArray) {}

  @Throws(Exception::class) open fun isListenPort(listenPort: Int): Boolean = false

  interface DuplexEventListener : EventListener {
    @Throws(Exception::class) fun onClientPacketReceived(data: ByteArray): Int

    @Throws(Exception::class) fun onServerPacketReceived(data: ByteArray): Int

    @Throws(Exception::class) fun onClientChunkArrived(data: ByteArray)

    @Throws(Exception::class) fun onServerChunkArrived(data: ByteArray)

    @Throws(Exception::class) fun onClientChunkPassThrough(): ByteArray?

    @Throws(Exception::class) fun onServerChunkPassThrough(): ByteArray?

    @Throws(Exception::class) fun onClientChunkAvailable(): ByteArray?

    @Throws(Exception::class) fun onServerChunkAvailable(): ByteArray?

    @Throws(Exception::class) fun onClientChunkReceived(data: ByteArray): ByteArray?

    @Throws(Exception::class) fun onServerChunkReceived(data: ByteArray): ByteArray?

    @Throws(Exception::class) fun onClientChunkSend(data: ByteArray): ByteArray?

    @Throws(Exception::class) fun onServerChunkSend(data: ByteArray): ByteArray?

    @Throws(Exception::class) fun onClientChunkSendForced(data: ByteArray): ByteArray?

    @Throws(Exception::class) fun onServerChunkSendForced(data: ByteArray): ByteArray?

    @Throws(Exception::class) fun onClientChunkFlowControl(data: ByteArray)

    @Throws(Exception::class) fun onServerChunkFlowControl(data: ByteArray)

    @Throws(Exception::class) fun closeClientChunkFlowControl()

    @Throws(Exception::class) fun closeServerChunkFlowControl()

    @Throws(Exception::class) fun getClientChunkFlowControlSink(): InputStream

    @Throws(Exception::class) fun getServerChunkFlowControlSink(): InputStream
  }
}
