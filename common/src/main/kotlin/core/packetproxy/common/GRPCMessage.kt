/*
 * Copyright 2019 shioshiota
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

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.util.StringJoiner
import net.arnx.jsonic.JSON
import org.xbill.DNS.utils.base64
import packetproxy.util.errWithStackTrace

class GRPCMessage {
  var type: Int
  var message: Map<String, Any?>

  constructor(bio: InputStream) {
    type = bio.read()
    var length = 0
    repeat(4) {
      length = length shl 8
      length += bio.read()
    }
    val raw = ByteArray(length)
    bio.read(raw)
    message =
      when (type) {
        GRPC_WEB_FH_DATA -> JSON.decode(Protobuf3.decode(raw))
        GRPC_WEB_FH_TRAILER ->
          mapOf("headers" to String(raw).split("\r\n").dropLastWhile { it.isEmpty() })
        else -> throw RuntimeException("Unknown GRPC Frame Type")
      }
  }

  constructor(json: Map<String, Any?>) {
    type = json["type"].toString().toInt()
    message = json["message"] as Map<String, Any?>
  }

  fun toBytes(): ByteArray {
    val bytes =
      when (type) {
        GRPC_WEB_FH_TRAILER -> {
          val joiner = StringJoiner("\r\n", "", "\r\n")
          for (header in message["headers"] as List<*>) joiner.add(header as String)
          joiner.toString().toByteArray()
        }
        GRPC_WEB_FH_DATA -> Protobuf3.encode(JSON.encode(message))
        else -> throw RuntimeException("Unknown GRPC Frame Type")
      }
    return ByteArrayOutputStream()
      .also {
        it.write(type)
        it.write(ByteBuffer.allocate(4).putInt(bytes.size).array())
        it.write(bytes)
      }
      .toByteArray()
  }

  companion object {
    private val GRPC_WEB_FH_DATA = 0b0
    private val GRPC_WEB_FH_TRAILER = 0b10000000

    @JvmStatic
    fun decodeTextMessages(base64Str: String): List<GRPCMessage> =
      decodeMessages(base64.fromString(base64Str))

    @JvmStatic
    fun decodeMessages(bytes: ByteArray): List<GRPCMessage> {
      val bio = ByteArrayInputStream(bytes)
      val result = ArrayList<GRPCMessage>()
      while (bio.available() > 0) result.add(GRPCMessage(bio))
      return result
    }

    @JvmStatic
    fun encodeTextMessages(messages: List<Map<String, Any?>>): String =
      String(
        encodeMessages(messages) {
          try {
            base64.toString(it.toBytes()).toByteArray()
          } catch (e: Exception) {
            errWithStackTrace(e)
            ByteArray(0)
          }
        }
      )

    @JvmStatic
    fun encodeMessages(messages: List<Map<String, Any?>>): ByteArray =
      encodeMessages(messages) {
        try {
          it.toBytes()
        } catch (e: Exception) {
          errWithStackTrace(e)
          ByteArray(0)
        }
      }

    private fun encodeMessages(
      messages: List<Map<String, Any?>>,
      encode: (GRPCMessage) -> ByteArray,
    ): ByteArray {
      val buffer = ByteArrayOutputStream()
      for (message in messages) buffer.writeBytes(encode(GRPCMessage(message)))
      return buffer.toByteArray()
    }
  }
}
