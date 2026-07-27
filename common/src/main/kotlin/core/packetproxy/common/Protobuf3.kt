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
package packetproxy.common

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.TreeMap
import packetproxy.util.Logging.err

class Protobuf3 {
  class Key {
    enum class Type {
      Variant,
      Bit64,
      LengthDelimited,
      StartGroup,
      EndGroup,
      Bit32,
      None,
      Reserved,
    }

    val fieldNumber: Long
    val wireType: Type

    constructor(fieldNumber: Long, wireType: Type) {
      this.fieldNumber = fieldNumber
      this.wireType = wireType
    }

    constructor(keyData: Long) {
      fieldNumber = keyData shr 3
      wireType = Type.entries[(keyData and 0x07).toInt()]
    }

    constructor(data: ByteArrayInputStream) : this(Protobuf3.decodeVar(data))

    override fun toString(): String = "Key[FieldNum:$fieldNumber, Type:$wireType]"

    fun writeTo(output: ByteArrayOutputStream) {
      Protobuf3.writeVar((fieldNumber shl 3) or (wireType.ordinal.toLong() and 7), output)
    }
  }

  companion object {
    @JvmStatic
    fun validateVar(input: ByteArrayInputStream): Boolean {
      val raw = ByteArray(input.available())
      input.mark(input.available())
      input.read(raw, 0, input.available())
      val result = validateVar(raw)
      input.reset()
      return result
    }

    @JvmStatic fun validateVar(input: ByteArray): Boolean = validateVar(input, null)

    @JvmStatic
    fun validateVar(input: ByteArray, outLength: IntArray?): Boolean {
      if (input.isEmpty()) return false
      var index = 0
      while (input.isNotEmpty()) {
        val next = input[index].toLong() and 0xff
        index++
        if (index >= 2 && next == 0L) return false
        if ((next and 0x80) == 0L) break
        if (index > 9 || index == input.size) return false
      }
      outLength?.set(0, index)
      return true
    }

    @JvmStatic
    fun decodeVar(input: ByteArrayInputStream): Long {
      var result = 0L
      var index = 0
      while (input.available() > 0) {
        val next = input.read().toLong() and 0xff
        result = result or ((next and 0x7f) shl (7 * index))
        if ((next and 0x80) == 0L) break
        index++
      }
      return result
    }

    @JvmStatic
    fun writeVar(value: Long, output: ByteArrayOutputStream) {
      var current = value
      for (index in 1..10) {
        val byte = (current and 0x7f).toInt()
        current = if (index == 10) 0 else current ushr 7
        if (current == 0L) {
          output.write(byte)
          break
        }
        output.write(byte or 0x80)
      }
    }

    @JvmStatic fun validateBit64(input: ByteArrayInputStream): Boolean = input.available() >= 8

    @JvmStatic fun validateBit64(input: ByteArray): Boolean = input.size >= 8

    @JvmStatic
    fun decodeBit64(input: ByteArrayInputStream): Long {
      var result = 0L
      repeat(8) { index -> result = result or (input.read().toLong() shl (8 * index)) }
      return result
    }

    @JvmStatic fun validateBit32(input: ByteArrayInputStream): Boolean = input.available() >= 4

    @JvmStatic fun validateBit32(input: ByteArray): Boolean = input.size >= 4

    @JvmStatic
    fun decodeBit32(input: ByteArrayInputStream): Int {
      var result = 0
      repeat(4) { index -> result = result or (input.read() shl (8 * index)) }
      return result
    }

    @JvmStatic
    fun validateRepeatedStrictly(input: ByteArray): Boolean {
      var index = 0
      var entries = 0
      while (index < input.size) {
        val length = IntArray(1)
        if (!validateVar(input.copyOfRange(index, input.size), length)) return false
        index += length[0]
        entries++
      }
      return entries <= 64 && index == input.size
    }

    @JvmStatic
    fun decodeRepeated(input: ByteArrayInputStream): List<Any> = buildList {
      while (input.available() > 0) add(decodeVar(input))
    }

    @JvmStatic
    fun decodeBytes(rawSubData: ByteArray): String =
      rawSubData.joinToString(":") { "%02x".format(it) }

    @JvmStatic
    fun encodeBytes(bytes: String): ByteArray =
      Binary(Binary.HexString(bytes.replace(":", ""))).toByteArray()

    @JvmStatic
    fun decode(input: ByteArray): String {
      val messages = TreeMap<String, Any?>()
      decodeData(ByteArrayInputStream(input), messages)
      return ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(messages)
    }

    @JvmStatic
    fun encode(input: String): ByteArray {
      val mapper = ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
      val messages: HashMap<String, Any?> =
        mapper.readValue(input, object : TypeReference<HashMap<String, Any?>>() {})
      return encodeData(messages)
    }

    @JvmStatic
    fun decodeData(data: ByteArrayInputStream, messages: MutableMap<String, Any?>): Boolean {
      var ordinary = 0
      while (data.available() > 0) {
        val key = Key(data)
        when (key.wireType) {
          Key.Type.Variant -> {
            if (!validateVar(data)) return false
            messages["%04x:%04x:Varint".format(key.fieldNumber, ordinary)] = decodeVar(data)
          }
          Key.Type.Bit32 -> {
            if (!validateBit32(data)) return false
            messages["%04x:%04x:32-bit".format(key.fieldNumber, ordinary)] = decodeBit32(data)
          }
          Key.Type.Bit64 -> {
            if (!validateBit64(data)) return false
            messages["%04x:%04x:64-bit".format(key.fieldNumber, ordinary)] = decodeBit64(data)
          }
          Key.Type.LengthDelimited -> {
            if (!validateVar(data)) return false
            val length = decodeVar(data)
            if (length > data.available()) return false
            val raw = ByteArray(length.toInt())
            data.read(raw, 0, length.toInt())
            val prefix = "%04x:%04x".format(key.fieldNumber, ordinary)
            when {
              StringUtils.validatePrintableUTF8(raw) ->
                messages["$prefix:String"] = String(raw, Charsets.UTF_8)
              else -> {
                val embedded = TreeMap<String, Any?>()
                if (decodeData(ByteArrayInputStream(raw), embedded)) {
                  messages["$prefix:embedded message"] = embedded
                } else if (validateRepeatedStrictly(raw)) {
                  messages["$prefix:repeated"] = decodeRepeated(ByteArrayInputStream(raw))
                } else {
                  messages["$prefix:bytes"] = decodeBytes(raw)
                }
              }
            }
          }
          else -> return false
        }
        ordinary++
      }
      return true
    }

    @JvmStatic
    fun encodeData(messages: Map<String, Any?>): ByteArray {
      val output = ByteArrayOutputStream()
      val ordered = TreeMap<String, String>()
      for (key in messages.keys) {
        val values = key.split(":")
        ordered["${values[1]}-$key"] = key
      }
      for (key in ordered.values) {
        val values = key.split(":")
        val fieldNumber = values[0].toLong(16)
        when (values[2]) {
          "Varint" -> {
            Key(fieldNumber, Key.Type.Variant).writeTo(output)
            writeVar((messages[key] as Number).toLong(), output)
          }
          "String" -> {
            Key(fieldNumber, Key.Type.LengthDelimited).writeTo(output)
            val bytes = messages[key].toString().toByteArray()
            writeVar(bytes.size.toLong(), output)
            output.write(bytes)
          }
          "32-bit" -> {
            Key(fieldNumber, Key.Type.Bit32).writeTo(output)
            output.write(
              ByteBuffer.allocate(4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(messages[key] as Int)
                .array()
            )
          }
          "64-bit" -> {
            Key(fieldNumber, Key.Type.Bit64).writeTo(output)
            output.write(
              ByteBuffer.allocate(8)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong((messages[key] as Number).toLong())
                .array()
            )
          }
          "repeated" -> {
            Key(fieldNumber, Key.Type.LengthDelimited).writeTo(output)
            val temporary = ByteArrayOutputStream()
            for (value in messages[key] as List<*>) {
              if (value !is Number) err("Unknown object type")
              else writeVar(value.toLong(), temporary)
            }
            writeVar(temporary.size().toLong(), output)
            output.write(temporary.toByteArray())
          }
          "embedded message" -> {
            Key(fieldNumber, Key.Type.LengthDelimited).writeTo(output)
            val temporary = encodeData(messages[key] as Map<String, Any?>)
            writeVar(temporary.size.toLong(), output)
            output.write(temporary)
          }
          "bytes" -> {
            Key(fieldNumber, Key.Type.LengthDelimited).writeTo(output)
            val bytes = encodeBytes(messages[key] as String)
            writeVar(bytes.size.toLong(), output)
            output.write(bytes)
          }
          else -> err("Unknown type: %s", values[2])
        }
      }
      return output.toByteArray()
    }
  }
}
