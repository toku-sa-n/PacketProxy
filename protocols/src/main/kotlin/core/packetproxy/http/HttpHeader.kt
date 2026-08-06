/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.http

import java.nio.charset.StandardCharsets
import java.util.Optional
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.Utils
import packetproxy.util.errWithStackTrace

class HttpHeader(rawHttp: ByteArray) {
  private var statusLine: String
  @JvmField var fields: MutableList<HeaderField>
  private var newLineSymbol: String

  init {
    var data = rawHttp
    newLineSymbol = lookUpNewLineSymbol(data)
    var newLineStr = newLineSymbol
    // パケットの先頭に改行が含まれているパターンがあるので回避
    if (Utils.indexOf(data, 0, newLineSymbol.length, newLineSymbol.toByteArray()) >= 0) {
      data = ArrayUtils.subarray(data, newLineSymbol.length, data.size)
    }
    var headerDelim = (newLineStr + newLineStr).toByteArray(StandardCharsets.UTF_8)
    var headerPos = Utils.indexOf(data, 0, data.size, headerDelim)
    if (headerPos < 0) {
      headerPos = data.size
    }
    var header = toUTF8(ArrayUtils.subarray(data, 0, headerPos))
    var lines = header.split(newLineStr)
    statusLine = lines[0]
    fields = lines.subList(1, lines.size).map { HeaderField(it) }.toMutableList()
  }

  fun getHeader(name: String): Optional<HeaderField> =
    fields.stream().filter { h -> h.getName().equals(name, ignoreCase = true) }.findFirst()

  fun getValue(name: String): Optional<String> = getHeader(name).map { it.getValue() }

  fun getAll(name: String): List<HeaderField> =
    fields.filter { h -> h.getName().equals(name, ignoreCase = true) }

  fun getAllValue(name: String): List<String> = getAll(name).map { it.getValue() }

  fun getFields(): List<HeaderField> = fields

  fun update(name: String, value: String) {
    fields.removeIf { h -> h.getName().equals(name, ignoreCase = true) }
    fields.add(HeaderField(name, value))
  }

  fun removeAll(name: String) {
    fields.removeIf { h -> h.getName().equals(name, ignoreCase = true) }
  }

  fun removeMatches(regex: String) {
    fields.removeIf { h -> h.getName().matches(Regex(regex)) }
  }

  fun getStatusline(): String = statusLine

  fun toByteArray(): ByteArray =
    fields
      .joinToString(separator = newLineSymbol, postfix = newLineSymbol) { it.toString() }
      .toByteArray()

  private fun toUTF8(raw: ByteArray): String {
    try {
      return String(raw, StandardCharsets.UTF_8)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    return ""
  }

  private fun lookUpNewLineSymbol(input: ByteArray): String {
    var hasCR = ArrayUtils.contains(input, 13.toByte())
    var hasLF = ArrayUtils.contains(input, 10.toByte())
    if (hasCR && hasLF) return toUTF8(crLf)
    if (hasCR) return toUTF8(cr)
    return toUTF8(lf)
  }

  companion object {
    private val crLf = byteArrayOf(13, 10)
    private val cr = byteArrayOf(13)
    private val lf = byteArrayOf(10)

    // TODO そのうちprivateに出来るように色々分離
    @JvmStatic
    fun calcHeaderSize(data: ByteArray): Int {
      for (i in data.indices) {
        if (
          i <= data.size - 4 &&
            data[i] == '\r'.code.toByte() &&
            data[i + 1] == '\n'.code.toByte() &&
            data[i + 2] == '\r'.code.toByte() &&
            data[i + 3] == '\n'.code.toByte()
        ) {
          return i + 4
        }
        if (
          i <= data.size - 2 && data[i] == '\n'.code.toByte() && data[i + 1] == '\n'.code.toByte()
        ) {
          return i + 2
        }
      }
      return -1
    }

    // first lineとheaderの末尾を確認する
    @JvmStatic
    fun isHTTPHeader(data: ByteArray): Boolean {
      // Headerサイズは正
      if (calcHeaderSize(data) == -1) {
        return false
      }
      // first line取得
      var index = ArrayUtils.indexOf(data, '\n'.code.toByte())
      if (index < 0) {
        return false
      }
      if (index > 0 && data[index - 1] == '\r'.code.toByte()) {
        index--
      }
      var line = data.copyOfRange(0, index)
      // first lineに制御文字は無い
      for (i in line.indices) {
        if (line[i] < 0x20 || 0x7f <= line[i]) {
          return false
        }
      }
      // first lineはスペース区切りでmethod pas, HTTP/?.?になってる
      var strs = String(line, StandardCharsets.UTF_8).split(" ")
      if (strs.size != 3) {
        return false
      }
      if (!strs[2].matches(Regex("HTTP/[0-9.]+"))) {
        return false
      }
      return true
    }
  }
}
