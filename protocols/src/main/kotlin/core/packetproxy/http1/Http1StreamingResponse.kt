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
package packetproxy.http1

import java.io.ByteArrayOutputStream
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.StringUtils
import packetproxy.http.Http
import packetproxy.model.Packets
import packetproxy.util.errWithStackTrace

class Http1StreamingResponse(private val packets: Packets) {
  private val clientInput = ByteArrayOutputStream()
  private val serverInput = ByteArrayOutputStream()
  private val buffer = ByteArrayOutputStream()
  private val headerBuffer = ByteArrayOutputStream()
  private var headerReceived = false

  @Throws(Exception::class)
  fun checkRequestDelimiter(data: ByteArray): Int = Http.parseHttpDelimiter(data)

  @Throws(Exception::class)
  fun clientRequestArrived(data: ByteArray) {
    clientInput.write(data)
  }

  @Throws(Exception::class) fun passThroughClientRequest(): ByteArray? = null

  @Throws(Exception::class)
  fun clientRequestAvailable(): ByteArray {
    val ret = clientInput.toByteArray()
    clientInput.reset()
    return ret
  }

  @Throws(Exception::class) fun decodeClientRequest(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class) fun encodeClientRequest(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class) fun checkResponseDelimiter(data: ByteArray): Int = data.size

  @Throws(Exception::class)
  fun serverResponseArrived(data: ByteArray) {
    serverInput.write(data)
  }

  @Throws(Exception::class)
  fun passThroughServerResponse(): ByteArray {
    buffer.write(serverInput.toByteArray())
    if (!headerReceived) {
      val endOfHeader = StringUtils.binaryFind(buffer.toByteArray(), "\r\n\r\n".toByteArray())
      if (endOfHeader > 0) {
        val header = ArrayUtils.subarray(buffer.toByteArray(), 0, endOfHeader + 2)!!
        val body = ArrayUtils.subarray(buffer.toByteArray(), endOfHeader + 4, buffer.size())!!
        val uuidHeader =
          String.format("X-PacketProxy-HTTP1-UUID: %s\r\n\r\n", StringUtils.randomUUID())
            .toByteArray()
        val newHeader = header + uuidHeader
        val newHttp = newHeader + body
        buffer.reset()
        buffer.write(newHttp)
        headerBuffer.write(newHeader)
        headerReceived = true
      }
    } else {
      val http: Http
      val delim = Http.parseHttpDelimiter(buffer.toByteArray())
      if (delim > 0) {
        val httpData = ArrayUtils.subarray(buffer.toByteArray(), 0, delim)
        val remaining = ArrayUtils.subarray(buffer.toByteArray(), delim, buffer.size())
        headerReceived = false
        buffer.reset()
        buffer.write(remaining!!)
        http = Http.create(httpData)
      } else {
        http = Http.create(buffer.toByteArray())
      }
      val guiHistoryUpdater = Thread {
        try {
          if (http.getBody() != null && http.getBody().isNotEmpty()) {
            val matchingPackets =
              packets.queryFullText(http.getFirstHeader("X-PacketProxy-HTTP1-UUID"))
            for (packet in matchingPackets) {
              val p = packets.query(packet.getId()) ?: return@Thread
              p.setDecodedData(http.toByteArray())
              p.setModifiedData(http.toByteArray())
              packets.update(p)
            }
          }
        } catch (e: Exception) {
          errWithStackTrace(e)
        }
      }
      guiHistoryUpdater.start()
    }
    val out = serverInput.toByteArray()
    serverInput.reset()
    return out
  }

  @Throws(Exception::class)
  fun serverResponseAvailable(): ByteArray? {
    if (headerBuffer.size() == 0) return null
    val out = headerBuffer.toByteArray()
    headerBuffer.reset()
    return out
  }

  @Throws(Exception::class) fun decodeServerResponse(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class) fun encodeServerResponse(input_data: ByteArray): ByteArray? = null
}
