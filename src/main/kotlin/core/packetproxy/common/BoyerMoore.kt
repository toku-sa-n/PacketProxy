/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.common

import java.util.Arrays

class BoyerMoore(private val pattern: ByteArray) {
  private var charTable = IntArray(256 * (pattern.size + 1))

  init {
    var numberSoFar = 0
    var soFar = IntArray(256)
    var occurred = IntArray(8)
    Arrays.fill(charTable, -1)
    Arrays.fill(occurred, 0)
    for (i in pattern.indices) {
      var character1 = 0x00ff and pattern[i].toInt()
      var index = character1 + 256 * (i + 1)
      charTable[index] = i
      if (i > 0) {
        for (j in 0 until numberSoFar) {
          var character2 = soFar[j]
          if (character1 != character2)
            charTable[character2 + 256 * (i + 1)] = charTable[character2 + 256 * i]
        }
      }
      if (!exists(occurred, character1)) {
        soFar[numberSoFar++] = character1
        setBit(occurred, character1)
      }
    }
  }

  fun searchIn(text: ByteArray) = searchIn(text, 0)

  fun searchIn(text: ByteArray, offset: Int): Int {
    if (pattern.isNotEmpty() && (offset < 0 || offset >= text.size - pattern.size)) {
      throw ArrayIndexOutOfBoundsException()
    }
    return searchIn(text, offset, text.size)
  }

  fun getReadableTable(vararg chars: Char): String {
    var table = StringBuilder()
    var stringBuilder = StringBuilder()
    for (character in chars) stringBuilder.append(character).append(",")
    var columnNames = stringBuilder.toString().substring(0, stringBuilder.length - 1)
    table.append(columnNames).append("\n")
    for (i in charTable.indices step 256) {
      stringBuilder = StringBuilder()
      for (j in chars.indices) {
        var index = (chars[j].code and 0x00ff) + i
        stringBuilder.append(charTable[index])
        if (j != chars.size - 1) stringBuilder.append(",")
      }
      table.append(stringBuilder).append("\n")
    }
    return table.toString()
  }

  fun searchIn(text: ByteArray, offset: Int, endpos: Int): Int {
    if (offset < 0 || offset > text.size) throw ArrayIndexOutOfBoundsException()
    if (pattern.isNotEmpty() && endpos >= offset && pattern.size <= text.size) {
      var index = offset + pattern.size - 1
      while (index < minOf(text.size, endpos)) {
        var patternIndex = pattern.size - 1
        while (text[index] == pattern[patternIndex]) {
          if (patternIndex == 0) return index - offset
          patternIndex--
          index--
        }
        var tableIndex = 0x00ff and text[index].toInt()
        tableIndex += 256 * patternIndex
        var shift = pattern.size - 1 - charTable[tableIndex]
        index += shift
      }
    }
    return -1
  }

  private fun exists(bitset: IntArray, character: Int): Boolean {
    var quotient = character shr 5
    var remainder = character and 0x1f
    return (bitset[quotient] and (1 shl remainder)) != 0x00
  }

  private fun setBit(bitset: IntArray, character: Int) {
    var quotient = character shr 5
    var remainder = character and 0x1f
    bitset[quotient] = bitset[quotient] or (1 shl remainder)
  }
}
