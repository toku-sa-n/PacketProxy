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
import packetproxy.encode.Encoder

/** Mode-specific DuplexEventListener callbacks. Encoder flow-control hooks are wired separately. */
internal class DuplexEventHandlers(
  val onClientPacketReceived: (ByteArray) -> Int,
  val onServerPacketReceived: (ByteArray) -> Int,
  val onClientChunkReceived: (ByteArray) -> ByteArray?,
  val onServerChunkReceived: (ByteArray) -> ByteArray?,
  val onClientChunkSend: (ByteArray) -> ByteArray?,
  val onServerChunkSend: (ByteArray) -> ByteArray?,
  val onClientChunkSendForced: (ByteArray) -> ByteArray?,
  val onServerChunkSendForced: (ByteArray) -> ByteArray?,
)

/** Delegates DuplexEventListener encoder hooks to an Encoder instance. */
internal class DuplexEncoderHooks(private val encoder: Encoder) {
  fun onClientChunkArrived(data: ByteArray) {
    encoder.clientRequestArrived(data)
  }

  fun onServerChunkArrived(data: ByteArray) {
    encoder.serverResponseArrived(data)
  }

  fun onClientChunkPassThrough(): ByteArray? = encoder.passThroughClientRequest()

  fun onServerChunkPassThrough(): ByteArray? = encoder.passThroughServerResponse()

  fun onClientChunkAvailable(): ByteArray? = encoder.clientRequestAvailable()

  fun onServerChunkAvailable(): ByteArray? = encoder.serverResponseAvailable()

  fun onClientChunkFlowControl(data: ByteArray) {
    encoder.putToClientFlowControlledQueue(data)
  }

  fun onServerChunkFlowControl(data: ByteArray) {
    encoder.putToServerFlowControlledQueue(data)
  }

  fun closeClientChunkFlowControl() {
    encoder.closeClientFlowControlledQueue()
  }

  fun closeServerChunkFlowControl() {
    encoder.closeServerFlowControlledQueue()
  }

  fun getClientChunkFlowControlSink(): InputStream = encoder.getClientFlowControlledInputStream()

  fun getServerChunkFlowControlSink(): InputStream = encoder.getServerFlowControlledInputStream()
}

/**
 * Builds a DuplexEventListener by composing mode-specific handlers with shared encoder hooks. No
 * inheritance hierarchy — handlers own the mode differences.
 */
internal fun duplexEventListener(
  encoder: Encoder,
  handlers: DuplexEventHandlers,
): Duplex.DuplexEventListener {
  var hooks = DuplexEncoderHooks(encoder)
  return object : Duplex.DuplexEventListener {
    override fun onClientPacketReceived(data: ByteArray): Int =
      handlers.onClientPacketReceived(data)

    override fun onServerPacketReceived(data: ByteArray): Int =
      handlers.onServerPacketReceived(data)

    override fun onClientChunkReceived(data: ByteArray): ByteArray? =
      handlers.onClientChunkReceived(data)

    override fun onServerChunkReceived(data: ByteArray): ByteArray? =
      handlers.onServerChunkReceived(data)

    override fun onClientChunkSend(data: ByteArray): ByteArray? = handlers.onClientChunkSend(data)

    override fun onServerChunkSend(data: ByteArray): ByteArray? = handlers.onServerChunkSend(data)

    override fun onClientChunkSendForced(data: ByteArray): ByteArray? =
      handlers.onClientChunkSendForced(data)

    override fun onServerChunkSendForced(data: ByteArray): ByteArray? =
      handlers.onServerChunkSendForced(data)

    override fun onClientChunkArrived(data: ByteArray) {
      hooks.onClientChunkArrived(data)
    }

    override fun onServerChunkArrived(data: ByteArray) {
      hooks.onServerChunkArrived(data)
    }

    override fun onClientChunkPassThrough(): ByteArray? = hooks.onClientChunkPassThrough()

    override fun onServerChunkPassThrough(): ByteArray? = hooks.onServerChunkPassThrough()

    override fun onClientChunkAvailable(): ByteArray? = hooks.onClientChunkAvailable()

    override fun onServerChunkAvailable(): ByteArray? = hooks.onServerChunkAvailable()

    override fun onClientChunkFlowControl(data: ByteArray) {
      hooks.onClientChunkFlowControl(data)
    }

    override fun onServerChunkFlowControl(data: ByteArray) {
      hooks.onServerChunkFlowControl(data)
    }

    override fun closeClientChunkFlowControl() {
      hooks.closeClientChunkFlowControl()
    }

    override fun closeServerChunkFlowControl() {
      hooks.closeServerChunkFlowControl()
    }

    override fun getClientChunkFlowControlSink(): InputStream =
      hooks.getClientChunkFlowControlSink()

    override fun getServerChunkFlowControlSink(): InputStream =
      hooks.getServerChunkFlowControlSink()
  }
}
