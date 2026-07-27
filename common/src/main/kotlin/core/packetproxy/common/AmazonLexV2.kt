/*
 * Copyright 2025 DeNA Co., Ltd.
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

import java.io.ByteArrayOutputStream
import java.util.zip.CRC32

// ref: https://docs.aws.amazon.com/lexv2/latest/dg/event-stream-encoding.html
class AmazonLexV2(val messages: Array<Message>) {
  class Message(val headers: Array<MessageHeader>, val payload: ByteArray) {
    override fun equals(other: Any?): Boolean =
      other is Message &&
        headers.contentEquals(other.headers) &&
        payload.contentEquals(other.payload)

    override fun hashCode(): Int = 31 * headers.contentHashCode() + payload.contentHashCode()
  }

  data class MessageHeader(
    val headerName: String,
    val headerValueType: Byte,
    val valueString: String,
  )

  override fun equals(other: Any?): Boolean =
    other is AmazonLexV2 && messages.contentEquals(other.messages)

  override fun hashCode(): Int = messages.contentHashCode()

  companion object {
    @JvmStatic
    fun fromBytes(body: ByteArray?): AmazonLexV2 {
      val nonNullBody = requireNotNull(body) { "Body cannot be null or empty" }
      require(nonNullBody.isNotEmpty()) { "Body cannot be null or empty" }
      val messages = ArrayList<Message>()
      var pos = 0
      while (pos < nonNullBody.size) {
        val totalByteLength = readInt(nonNullBody, pos)
        pos += 4
        val headersByteLength = readInt(nonNullBody, pos)
        pos += 4
        readInt(nonNullBody, pos)
        pos += 4

        val headers = ArrayList<MessageHeader>()
        val headerAbsPos = pos + headersByteLength
        while (pos < headerAbsPos) {
          val headerNameByteLength = nonNullBody[pos++].toInt()
          val headerName = String(nonNullBody, pos, headerNameByteLength)
          pos += headerNameByteLength
          val headerValueType = nonNullBody[pos++]
          val valueStringByteLength =
            ((nonNullBody[pos++].toInt() and 0xff) shl 8) or (nonNullBody[pos++].toInt() and 0xff)
          val valueString = String(nonNullBody, pos, valueStringByteLength)
          pos += valueStringByteLength
          headers.add(MessageHeader(headerName, headerValueType, valueString))
        }

        val payload = nonNullBody.copyOfRange(pos, pos + totalByteLength - headersByteLength - 16)
        pos += payload.size
        readInt(nonNullBody, pos)
        pos += 4
        if (pos > nonNullBody.size) {
          throw Exception(
            "Invalid message length: $totalByteLength, pos: $pos, body length: ${nonNullBody.size}"
          )
        }
        messages.add(Message(headers.toTypedArray(), payload))
      }
      return AmazonLexV2(messages.toTypedArray())
    }

    @JvmStatic
    fun toBytes(lex: AmazonLexV2?): ByteArray {
      require(lex != null && lex.messages.isNotEmpty()) { "Lex messages cannot be null or empty" }
      val outputStream = ByteArrayOutputStream()
      for (message in lex.messages) {
        var totalByteLength = 16 + message.payload.size
        var headersByteLength = 0
        for (header in message.headers) {
          val headerByteLength = 1 + header.headerName.length + 1 + 2 + header.valueString.length
          headersByteLength += headerByteLength
          totalByteLength += headerByteLength
        }
        val baos = ByteArrayOutputStream()
        writeInt(baos, totalByteLength)
        writeInt(baos, headersByteLength)
        writeInt(baos, CRC32().also { it.update(baos.toByteArray()) }.value.toInt())

        for (header in message.headers) {
          baos.write(header.headerName.length)
          baos.write(header.headerName.toByteArray())
          baos.write(header.headerValueType.toInt())
          val valueBytes = header.valueString.toByteArray(Charsets.UTF_8)
          baos.write((valueBytes.size shr 8) and 0xff)
          baos.write(valueBytes.size and 0xff)
          baos.write(valueBytes)
        }
        baos.write(message.payload)
        writeInt(baos, CRC32().also { it.update(baos.toByteArray()) }.value.toInt())
        outputStream.write(baos.toByteArray())
      }
      return outputStream.toByteArray()
    }

    private fun readInt(bytes: ByteArray, offset: Int): Int =
      ((bytes[offset].toInt() and 0xff) shl 24) or
        ((bytes[offset + 1].toInt() and 0xff) shl 16) or
        ((bytes[offset + 2].toInt() and 0xff) shl 8) or
        (bytes[offset + 3].toInt() and 0xff)

    private fun writeInt(output: ByteArrayOutputStream, value: Int) {
      output.write((value shr 24) and 0xff)
      output.write((value shr 16) and 0xff)
      output.write((value shr 8) and 0xff)
      output.write(value and 0xff)
    }
  }
}
