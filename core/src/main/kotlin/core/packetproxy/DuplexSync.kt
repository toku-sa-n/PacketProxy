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
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.Endpoint
import packetproxy.model.OneShotPacket

class DuplexSync @Throws(Exception::class) constructor(private val server: Endpoint) : Duplex() {
  private val out: OutputStream = server.getOutputStream()
  private val `in`: InputStream = server.getInputStream()
  private val serverBuffer = ByteArrayOutputStream()

  companion object {
    @JvmStatic fun encodePacket(one_shot: OneShotPacket): OneShotPacket = one_shot
  }

  override fun isListenPort(listenPort: Int): Boolean = false

  @Throws(Exception::class) override fun createSameConnectionDuplex(): Duplex = DuplexSync(server)

  @Throws(Exception::class)
  override fun prepareFastSend(data: ByteArray): ByteArray? {
    val accepted_length = callOnClientPacketReceived(data)
    if (accepted_length <= 0) {
      return null
    }
    val accepted = ArrayUtils.subarray(data, 0, accepted_length)

    val pass = callOnClientChunkPassThrough()

    val decoded = super.callOnClientChunkReceived(accepted)
    val encoded = super.callOnClientChunkSend(decoded!!)
    return mergeChunk(pass, encoded)
  }

  @Throws(Exception::class)
  override fun execFastSend(data: ByteArray) {
    out.write(data)
    out.flush()
  }

  @Throws(Exception::class)
  override fun send(data: ByteArray) {
    val accepted_length = callOnClientPacketReceived(data)
    if (accepted_length <= 0) {
      return
    }
    val accepted = ArrayUtils.subarray(data, 0, accepted_length)

    val decoded = super.callOnClientChunkReceived(accepted)
    val encoded = super.callOnClientChunkSend(decoded!!)
    out.write(encoded)
    out.flush()
  }

  @Throws(Exception::class)
  override fun receive(): ByteArray? {
    val input_data = ByteArray(100 * 1024)

    val bout = ByteArrayOutputStream()

    while (true) {
      val buffered = serverBuffer.toByteArray()
      val packetLen = callOnServerPacketReceived(buffered)
      if (packetLen > 0) {
        val packetData = ArrayUtils.subarray(buffered, 0, packetLen)
        val restData = ArrayUtils.subarray(buffered, packetLen, buffered.size)
        serverBuffer.reset()
        serverBuffer.write(restData)

        callOnServerChunkArrived(packetData)

        var available_data = callOnServerChunkAvailable()
        if (available_data == null || available_data.isEmpty()) {
          continue
        }
        do {
          val decoded = callOnServerChunkReceived(available_data!!)
          bout.write(decoded)
          available_data = callOnServerChunkAvailable()
        } while (available_data != null && available_data.isNotEmpty())
        val encoded = callOnServerChunkSend(bout.toByteArray())
        return encoded
      }

      val length = `in`.read(input_data, 0, input_data.size)
      if (length < 0) {
        return null
      }
      serverBuffer.write(input_data, 0, length)
    }
  }

  @Throws(Exception::class)
  override fun close() {
    `in`.close()
    out.close()
  }

  private fun mergeChunk(pass: ByteArray?, encoded: ByteArray?): ByteArray {
    val encodedData = encoded ?: ByteArray(0)
    if (pass == null || pass.isEmpty()) {
      return encodedData
    }
    if (encodedData.isEmpty()) {
      return pass
    }
    return ByteArray(pass.size + encodedData.size).also {
      System.arraycopy(pass, 0, it, 0, pass.size)
      System.arraycopy(encodedData, 0, it, pass.size, encodedData.size)
    }
  }
}
