/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.common

import com.google.re2j.Pattern
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import net.arnx.jsonic.JSON
import org.apache.commons.lang3.ArrayUtils
import packetproxy.util.Logging

class StringUtils {
  companion object {
    private val secureRandom = SecureRandom()
    private const val HEX_ALPHABET = "0123456789abcdef"

    private fun randomFromAlphabet(length: Int, alphabet: String): String {
      val chars = CharArray(length)
      for (i in chars.indices) {
        chars[i] = alphabet[secureRandom.nextInt(alphabet.length)]
      }
      return String(chars)
    }

    @JvmStatic
    fun randomUUID(): String = buildString {
      append(randomFromAlphabet(8, HEX_ALPHABET))
      append("-")
      append(randomFromAlphabet(4, HEX_ALPHABET))
      append("-")
      append(randomFromAlphabet(4, HEX_ALPHABET))
      append("-")
      append(randomFromAlphabet(4, HEX_ALPHABET))
      append("-")
      append(randomFromAlphabet(12, HEX_ALPHABET))
    }

    @JvmStatic
    fun prettyUpJson(json: ByteArray): ByteArray =
      try {
        prettyUpJson(String(json)).toByteArray(Charsets.UTF_8)
      } catch (e: Exception) {
        Logging.errWithStackTrace(e)
        prettyUpJson(String(json)).toByteArray()
      }

    @JvmStatic
    fun prettyUpJson(json: String): String {
      var jsonMap = JSON.decode(json) as Map<*, *>
      var encoder = JSON()
      encoder.setPrettyPrint(true)
      encoder.setInitialIndent(0)
      encoder.setIndentText("    ")
      encoder.format(jsonMap)
      return encoder.format(jsonMap).replace("\\u003C", "<").replace("\\u003E", ">")
    }

    @JvmStatic fun minifyJson(json: ByteArray) = minifyJson(String(json)).toByteArray()

    @JvmStatic
    fun minifyJson(json: String): String {
      var jsonMap = JSON.decode(json) as Map<*, *>
      return JSON.encode(jsonMap)
    }

    @JvmStatic
    fun countChar(string: String, character: Char, startIdx: Int, endIdx: Int): Int {
      var count = 0
      var limit = minOf(string.length, endIdx)
      for (i in startIdx until limit) if (string[i] == character) count++
      return count
    }

    @JvmStatic
    fun hexToByte(hexa: ByteArray): ByteArray {
      var hex = String(hexa).trim()
      if (hex.length % 2 != 0) throw Exception(i18nString("Length of string is not multiples of 2"))
      var bytes = ByteArray(hex.length / 2)
      for (index in bytes.indices) bytes[index] =
        hex.substring(index * 2, (index + 1) * 2).toInt(16).toByte()
      return bytes
    }

    @JvmStatic
    fun byteToHex(bytes: ByteArray): String {
      var stringBuffer = StringBuffer(bytes.size * 2)
      for (byte in bytes) {
        var value = byte.toInt() and 0xff
        if (value < 0x10) stringBuffer.append("0")
        stringBuffer.append(value.toString(16))
      }
      return stringBuffer.toString()
    }

    @JvmStatic
    fun intToByte(value: Int, littleEndian: Boolean): ByteArray {
      var bytes = ByteArray(4)
      for (i in 0 until 4) bytes[i] = (0xff and (value shr (i * 8))).toByte()
      if (!littleEndian) ArrayUtils.reverse(bytes)
      return bytes
    }

    @JvmStatic
    fun intToHex(value: Int, littleEndian: Boolean) = byteToHex(intToByte(value, littleEndian))

    @JvmStatic
    fun pseudoBinaryPatternReplace(input: ByteArray, regex: String, replace: String): ByteArray {
      var input2 = input.clone()
      for (i in input2.indices) if (input2[i] < 0) input2[i] = 0x01
      var pseudoString = String(input2)
      var matcher = Pattern.compile(regex).matcher(pseudoString)
      var result = ByteArrayOutputStream()
      if (matcher.find()) {
        var matched = matcher.group(0)
        var from = pseudoString.indexOf(matched)
        result.write(input, 0, from)
        var replacement = replace.toByteArray()
        result.write(replacement, 0, replacement.size)
        result.write(input, from + matched.length, input.size - (from + matched.length))
      }
      return result.toByteArray()
    }

    @JvmStatic fun binaryFind(input: ByteArray, pattern: ByteArray) = binaryFind(input, pattern, 0)

    @JvmStatic
    fun binaryFind(input: ByteArray, pattern: ByteArray, fromIndex: Int): Int {
      var boyerMoore = BoyerMoore(pattern)
      var index = boyerMoore.searchIn(input, fromIndex)
      return if (index < 0) index else index + fromIndex
    }

    @JvmStatic
    fun binaryReplace(input: ByteArray, pattern: ByteArray, replace: ByteArray): ByteArray {
      if (pattern.size != replace.size)
        throw Exception(i18nString("Lengths of target and replacement are not same."))
      var result = input.clone()
      if (pattern.isEmpty()) return result
      var start = 0
      while (binaryFind(input, pattern, start).also { start = it } > 0) {
        for (j in replace.indices) result[start + j] = replace[j]
        start += pattern.size - 1
      }
      return result
    }

    @JvmStatic
    fun hexBinaryReplace(input: ByteArray, hexPattern: String, hexReplace: String) =
      binaryReplace(input, hexToByte(hexPattern.toByteArray()), hexToByte(hexReplace.toByteArray()))

    @JvmStatic
    fun toAscii(data: ByteArray): ByteArray {
      var result = data.clone()
      for (i in result.indices) if (result[i] < 0x20.toByte()) result[i] = '.'.code.toByte()
      return result
    }

    @JvmStatic
    fun validatePrintableUTF8(data: ByteArray): Boolean {
      var index = 0
      while (index < data.size) {
        var octet = data[index]
        if (octet == 0x0d.toByte() || octet == 0x0a.toByte()) {
          index++
          continue
        }
        if (octet > 0.toByte() && octet < 0x20.toByte() || octet == 0x7f.toByte()) return false
        if ((octet.toInt() and 0x80) == 0) {
          index++
          continue
        }
        var end =
          when {
            (octet.toInt() and 0xe0) == 0xc0 -> index + 1
            (octet.toInt() and 0xf0) == 0xe0 -> index + 2
            (octet.toInt() and 0xf8) == 0xf0 -> index + 3
            else -> return false
          }
        while (index < end) {
          index++
          octet = data[index]
          if ((octet.toInt() and 0xc0) != 0x80) return false
        }
        index++
      }
      return true
    }
  }
}
