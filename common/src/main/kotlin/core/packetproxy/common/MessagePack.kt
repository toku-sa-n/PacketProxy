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
package packetproxy.common

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.TreeMap
import packetproxy.util.err
import packetproxy.util.errWithStackTrace

class MessagePack {
  class Key {
    enum class Type {
      Integer,
      UnsignedInteger,
      Float,
      Boolean,
      RawString,
      RawBinary,
      Map,
      Array,
      Extension,
      Nil,
      None;

      companion object {
        @JvmStatic
        fun fromString(value: String): Type? =
          entries.firstOrNull { it.name.equals(value, ignoreCase = true) }
      }
    }

    var type = Type.None
    var size = -1
    var fix = false
    var value = 0

    constructor(firstByte: Byte) {
      init(firstByte)
    }

    constructor(type: Type, size: Int, fix: Boolean) {
      this.type = type
      this.size = size
      this.fix = fix
    }

    constructor(index: Int, type: Type, size: Int, fix: Boolean) : this(type, size, fix)

    fun init(firstByte: Byte) {
      val byte = firstByte.toInt() and 0xff
      when {
        byte <= 0x7f -> set(Type.Integer, 1, true, byte)
        byte in 0x80..0x8f -> set(Type.Map, byte - 0x80, true)
        byte in 0x90..0x9f -> set(Type.Array, byte - 0x90, true)
        byte in 0xa0..0xbf -> set(Type.RawString, byte - 0xa0, true)
        byte == 0xc0 -> set(Type.Nil, 1, true)
        byte == 0xc1 -> set(Type.None, 0, true)
        byte == 0xc2 -> set(Type.Boolean, 1, true, 0)
        byte == 0xc3 -> set(Type.Boolean, 1, true, 1)
        byte in 0xc4..0xc6 -> set(Type.RawBinary, 1 shl (byte - 0xc4), false)
        byte in 0xc7..0xc9 -> set(Type.Extension, 1 shl (byte - 0xc7), false)
        byte in 0xca..0xcb -> set(Type.Float, 4 shl (byte - 0xca), false)
        byte in 0xcc..0xcf -> set(Type.UnsignedInteger, 1 shl (byte - 0xcc), false)
        byte in 0xd0..0xd3 -> set(Type.Integer, 1 shl (byte - 0xd0), false)
        byte in 0xd4..0xd8 -> set(Type.Extension, 1 shl (byte - 0xd4), true)
        byte in 0xd9..0xdb -> set(Type.RawString, 1 shl (byte - 0xd9), false)
        byte in 0xdc..0xdd -> set(Type.Array, 2 shl (byte - 0xdc), false)
        byte in 0xde..0xdf -> set(Type.Map, 2 shl (byte - 0xde), false)
        else -> set(Type.Integer, 1, true, -1 * ((firstByte.toInt().inv()) + 1))
      }
    }

    fun fitType(number: Long) {
      when (type) {
        Type.Integer -> {
          if (fix && (number < -32 || number > 127)) {
            fix = false
            size = 0
          }
          if (fix) value = number.toInt()
          else if (size < integerSize(number)) size = integerSize(number)
        }
        Type.UnsignedInteger ->
          if (size < unsignedIntegerSize(number)) size = unsignedIntegerSize(number)
        Type.Boolean -> value = if (number == 0L) 0 else 1
        Type.RawString -> fitVariable(number, 32)
        Type.RawBinary -> if (size < unsignedIntegerSize(number)) size = unsignedIntegerSize(number)
        Type.Array,
        Type.Map -> {
          if (fix && number >= 16) {
            fix = false
            size = 0
          }
          if (fix) size = number.toInt()
          else {
            var newSize = unsignedIntegerSize(number)
            if (newSize == 1) newSize = 2
            if (size < newSize) size = newSize
          }
        }
        Type.Extension -> {
          if (fix && number !in listOf(1L, 2L, 4L, 8L, 16L)) {
            fix = false
            size = 0
          }
          if (fix) size = number.toInt()
          else if (size < unsignedIntegerSize(number)) size = unsignedIntegerSize(number)
        }
        else -> Unit
      }
    }

    fun toFirstByte(): Byte =
      when (type) {
        Type.Integer -> if (fix) value.toByte() else (0xd0 + rightmostBitPosition(size)).toByte()
        Type.UnsignedInteger -> (0xcc + rightmostBitPosition(size)).toByte()
        Type.Float -> (0xca + rightmostBitPosition(size) - 2).toByte()
        Type.Boolean -> (0xc2 + value).toByte()
        Type.RawString ->
          if (fix) (0xa0 + size).toByte() else (0xd9 + rightmostBitPosition(size)).toByte()
        Type.RawBinary -> (0xc4 + rightmostBitPosition(size)).toByte()
        Type.Map ->
          if (fix) (0x80 + size).toByte() else (0xde + rightmostBitPosition(size) - 1).toByte()
        Type.Array ->
          if (fix) (0x90 + size).toByte() else (0xdc + rightmostBitPosition(size) - 1).toByte()
        Type.Extension ->
          if (fix) (0xd4 + rightmostBitPosition(size)).toByte()
          else (0xc7 + rightmostBitPosition(size)).toByte()
        Type.Nil -> 0xc0.toByte()
        Type.None -> 0xc1.toByte()
      }

    override fun toString(): String = "Key[Type:$type, Size: $size, Fix: ${if (fix) 1 else 0}]"

    private fun set(type: Type, size: Int, fix: Boolean, value: Int = 0) {
      this.type = type
      this.size = size
      this.fix = fix
      this.value = value
    }

    private fun fitVariable(number: Long, limit: Int) {
      if (fix && number >= limit) {
        fix = false
        size = 0
      }
      if (fix) size = number.toInt()
      else if (size < unsignedIntegerSize(number)) size = unsignedIntegerSize(number)
    }

    private fun rightmostBitPosition(number: Int): Int =
      (0 until 64).firstOrNull { (number shr it) and 1 == 1 } ?: 0

    private fun integerSize(number: Long): Int =
      when {
        number in -128..127 -> 1
        number in -32768..32767 -> 2
        number in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong() -> 4
        else -> 8
      }

    private fun unsignedIntegerSize(number: Long): Int =
      when {
        number <= 255 -> 1
        number <= 65535 -> 2
        number <= 4294967295L -> 4
        else -> 8
      }
  }

  companion object {
    @JvmStatic
    fun decode(inputData: ByteArray): String {
      val messages = TreeMap<String, Any?>()
      decodeData(0, ByteArrayInputStream(inputData), messages)
      return ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(messages)
    }

    @JvmStatic
    fun decodeData(
      ordinary: Int,
      input: ByteArrayInputStream,
      messages: MutableMap<String, Any?>,
    ): Boolean {
      return try {
        if (input.available() == 0) {
          err("MessagePack Parse failed: out of range")
          return false
        }
        val key = Key(input.read().toByte())
        val value: Any? =
          when (key.type) {
            Key.Type.Integer -> if (key.fix) key.value else decodeInteger(key.size, true, input)
            Key.Type.UnsignedInteger -> decodeInteger(key.size, false, input)
            Key.Type.Float -> if (key.size == 4) decodeFloat(input) else decodeDouble(input)
            Key.Type.Boolean -> key.value
            Key.Type.RawString ->
              decodeString(
                if (key.fix) key.size else decodeInteger(key.size, false, input).toInt(),
                input,
              )
            Key.Type.RawBinary -> decodeBinary(decodeInteger(key.size, false, input).toInt(), input)
            Key.Type.Map -> {
              val length = if (key.fix) key.size else decodeInteger(key.size, false, input).toInt()
              ArrayList<Any?>().also { list ->
                repeat(2 * length) {
                  val child = TreeMap<String, Any?>()
                  if (!decodeData(it, input, child)) return false
                  list.add(child)
                }
              }
            }
            Key.Type.Array -> {
              val length = if (key.fix) key.size else decodeInteger(key.size, false, input).toInt()
              ArrayList<Any?>().also { list ->
                repeat(length) {
                  val child = TreeMap<String, Any?>()
                  if (!decodeData(it, input, child)) return false
                  list.add(child)
                }
              }
            }
            Key.Type.Extension -> {
              val length = if (key.fix) key.size else decodeInteger(key.size, false, input).toInt()
              "${decodeInteger(1, false, input)}:${decodeBinary(length, input)}"
            }
            else -> null
          }
        messages[keyString(key, ordinary)] = value
        true
      } catch (e: Exception) {
        errWithStackTrace(e)
        false
      }
    }

    @JvmStatic
    fun keyString(key: Key, ordinary: Int): String =
      "%02d:%s:%01d:%01d".format(ordinary, key.type, key.size, if (key.fix) 1 else 0)

    @JvmStatic
    fun encode(input: String): ByteArray {
      val messages: HashMap<String, Any?> =
        ObjectMapper().readValue(input, object : TypeReference<HashMap<String, Any?>>() {})
      return ByteArrayOutputStream().also { encodeData(messages, it) }.toByteArray()
    }

    @JvmStatic
    fun encodeData(messages: Map<String, Any?>, output: ByteArrayOutputStream) {
      for (keyString in messages.keys.sorted()) {
        val parts = keyString.split(":")
        val key = Key(Key.Type.fromString(parts[1])!!, parts[2].toInt(), parts[3].toInt() == 1)
        val message = messages[keyString]
        when (key.type) {
          Key.Type.Integer,
          Key.Type.UnsignedInteger -> {
            val value = (message as Number).toLong()
            key.fitType(value)
            output.write(key.toFirstByte().toInt())
            if (!key.fix) output.write(encodeInteger(key.size, false, value))
          }
          Key.Type.Float -> {
            output.write(key.toFirstByte().toInt())
            output.write(
              if (key.size == 4) encodeFloat((message as Number).toFloat())
              else encodeDouble((message as Number).toDouble())
            )
          }
          Key.Type.Boolean -> {
            key.fitType((message as Number).toLong())
            output.write(key.toFirstByte().toInt())
          }
          Key.Type.RawString,
          Key.Type.RawBinary -> {
            val bytes =
              if (key.type == Key.Type.RawString) encodeString(message as String)
              else encodeBinary(message as String)
            key.fitType(
              if (key.type == Key.Type.RawString) (message as String).length.toLong()
              else bytes.size.toLong()
            )
            output.write(key.toFirstByte().toInt())
            if (!key.fix) output.write(encodeInteger(key.size, false, bytes.size.toLong()))
            output.write(bytes)
          }
          Key.Type.Map,
          Key.Type.Array -> {
            val list = message as List<*>
            val length = if (key.type == Key.Type.Map) list.size / 2 else list.size
            key.fitType(length.toLong())
            output.write(key.toFirstByte().toInt())
            if (!key.fix) output.write(encodeInteger(key.size, false, length.toLong()))
            for (child in list) encodeData(child as Map<String, Any?>, output)
          }
          Key.Type.Extension -> {
            val (type, data) = (message as String).split(":", limit = 2)
            val bytes = encodeBinary(data)
            key.fitType(bytes.size.toLong())
            output.write(key.toFirstByte().toInt())
            if (!key.fix) output.write(encodeInteger(key.size, false, bytes.size.toLong()))
            output.write(type.toInt())
            output.write(bytes)
          }
          else -> output.write(key.toFirstByte().toInt())
        }
      }
    }

    @JvmStatic
    fun decodeInteger(size: Int, signed: Boolean, input: ByteArrayInputStream): Long {
      if (input.available() < size) throw Exception("MessagePack Parse failed: out of range")
      var result = 0L
      var firstBit = 0L
      repeat(size) {
        val next = input.read().toLong()
        result = (result shl 8) or next
        if (it == 0) firstBit = (next shr 7) and 1
      }
      if (signed && firstBit == 1L)
        repeat(8 - size) { index -> result = result or (0xffL shl (8 * (index + size))) }
      return result
    }

    @JvmStatic
    fun encodeInteger(size: Int, signed: Boolean, value: Long): ByteArray =
      ByteArray(size) { index -> ((value shr (8 * (size - index - 1))) and 0xff).toByte() }

    @JvmStatic
    fun decodeFloat(input: ByteArrayInputStream): Float {
      if (input.available() < 4) throw Exception("MessagePack Parse failed: out of range")
      return DataInputStream(input).readFloat()
    }

    @JvmStatic
    fun encodeFloat(value: Float): ByteArray =
      ByteArrayOutputStream().also { DataOutputStream(it).writeFloat(value) }.toByteArray()

    @JvmStatic
    fun decodeDouble(input: ByteArrayInputStream): Double {
      if (input.available() < 8) throw Exception("MessagePack Parse failed: out of range")
      return DataInputStream(input).readDouble()
    }

    @JvmStatic
    fun encodeDouble(value: Double): ByteArray =
      ByteArrayOutputStream().also { DataOutputStream(it).writeDouble(value) }.toByteArray()

    @JvmStatic
    fun decodeString(length: Int, input: ByteArrayInputStream): String {
      if (input.available() < length) throw Exception("MessagePack Parse failed: out of range")
      return String(input.readNBytes(length))
    }

    @JvmStatic fun encodeString(value: String): ByteArray = value.toByteArray()

    @JvmStatic
    fun decodeBinary(length: Int, input: ByteArrayInputStream): String {
      if (input.available() < length) throw Exception("MessagePack Parse failed: out of range")
      return StringUtils.byteToHex(input.readNBytes(length))
    }

    @JvmStatic
    fun encodeBinary(value: String): ByteArray = StringUtils.hexToByte(value.toByteArray())
  }
}
