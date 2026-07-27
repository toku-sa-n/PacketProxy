/*
 * Copyright 2019,2023 DeNA Co., Ltd.
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
package packetproxy.websocket

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex

class WebSocketFrame
private constructor(val opcode: OpCode?, val payload: ByteArray, val maskEnabled: Boolean) {
  @Throws(Exception::class)
  fun getBytes(): ByteArray {
    val buffer = ByteBuffer.allocate(payload.size + 14)
    buffer.put((0x80 or opcode!!.code).toByte())
    val maskFlg = if (maskEnabled) 0x80.toByte() else 0x00.toByte()
    when {
      payload.size < 126 -> buffer.put((payload.size or maskFlg.toInt()).toByte())
      payload.size < 32768 -> {
        buffer.put((126 or maskFlg.toInt()).toByte())
        buffer.putShort(payload.size.toShort())
      }
      else -> {
        buffer.put((127 or maskFlg.toInt()).toByte())
        buffer.putInt(payload.size)
      }
    }
    if (maskEnabled) {
      val mask = Hex.decodeHex("0A0A0A0A")
      buffer.put(mask)
      buffer.put(encodeMask(payload, mask))
    } else {
      buffer.put(payload)
    }
    buffer.flip()
    return ByteArray(buffer.remaining()).also(buffer::get)
  }

  companion object {
    @JvmStatic
    fun checkDelimiter(data: ByteArray): Int {
      var finFlg = false
      var index = 0
      while (!finFlg) {
        if (empty(data, index)) {
          return -1
        }
        finFlg = data[index].toInt() and 0x80 != 0
        var length = 1
        if (empty(data, index + 1)) {
          return -1
        }
        val maskAndLength = data[index + 1].toInt() and 0xff
        length += 1
        length += if (maskAndLength and 0x80 != 0) 4 else 0
        when (val lengthType = maskAndLength and 0x7f) {
          in 0 until 126 -> length += lengthType
          126 -> {
            if (empty(data, index + 2) || empty(data, index + 3)) {
              return -1
            }
            length += 2
            length +=
              ((data[index + 2].toInt() and 0xff) shl 8) + (data[index + 3].toInt() and 0xff)
          }
          else -> {
            if (
              empty(data, index + 2) ||
                empty(data, index + 3) ||
                empty(data, index + 4) ||
                empty(data, index + 5)
            ) {
              return -1
            }
            length += 4
            length +=
              ((data[index + 2].toInt() and 0xff) shl 24) +
                ((data[index + 3].toInt() and 0xff) shl 16) +
                ((data[index + 4].toInt() and 0xff) shl 8) +
                (data[index + 5].toInt() and 0xff)
          }
        }
        if (empty(data, index + length - 1)) {
          return -1
        }
        index += length
      }
      return index
    }

    @JvmStatic
    @Throws(Exception::class)
    fun parse(bytes: ByteArray): WebSocketFrame = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    @Throws(Exception::class)
    fun parse(buffer: ByteBuffer): WebSocketFrame {
      val payloads = ByteArrayOutputStream()
      var opcode: OpCode? = null
      var finFlg: Boolean
      var maskFlg: Boolean

      do {
        val finOp = buffer.get()
        finFlg = finOp.toInt() and 0x80 != 0
        if (opcode == null) {
          opcode = OpCode.fromInt(finOp.toInt() and 0x0f)
        }
        val maskAndLength = buffer.get()
        maskFlg = maskAndLength.toInt() and 0x80 != 0
        val length =
          when (val lengthType = maskAndLength.toInt() and 0x7f) {
            in 0 until 126 -> lengthType
            126 -> buffer.short.toInt()
            else -> buffer.int
          }
        val mask = if (maskFlg) ByteArray(4).also(buffer::get) else null
        if (length > 0) {
          val payload = decodeMask(ByteArray(length).also(buffer::get), mask)
          payloads.write(payload)
        }
      } while (!finFlg)

      return of(opcode, payloads.toByteArray(), maskFlg)
    }

    @JvmStatic
    fun of(payload: ByteArray, maskEnabled: Boolean): WebSocketFrame =
      of(OpCode.Binary, payload, maskEnabled)

    @JvmStatic
    fun of(opcode: OpCode?, payload: ByteArray, maskEnabled: Boolean): WebSocketFrame =
      WebSocketFrame(opcode, payload, maskEnabled)

    private fun empty(data: ByteArray, index: Int): Boolean = index >= data.size

    private fun encodeMask(data: ByteArray, key: ByteArray?): ByteArray {
      check(key == null || key.size == 4)
      val result = data.clone()
      if (key == null) {
        return result
      }
      for (index in data.indices) {
        result[index] = (result[index].toInt() xor key[index % 4].toInt()).toByte()
      }
      return result
    }

    private fun decodeMask(data: ByteArray, key: ByteArray?): ByteArray = encodeMask(data, key)
  }
}
