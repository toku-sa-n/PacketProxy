/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.common

import java.nio.ByteBuffer
import java.nio.ByteOrder

class Binary {
  class HexString(private val str: String) {
    override fun toString() = str
  }

  class AsciiString(private val str: String) {
    override fun toString() = str
  }

  private var hexarray: ByteArray
  private var intToAsciiString = arrayOfNulls<String>(256)
  private var intToHexString = arrayOfNulls<String>(256)

  constructor(hexArray: ByteArray) {
    hexarray = hexArray
  }

  constructor(hexstr: HexString) {
    hexarray = createHexarrayFromHexstr(hexstr)
  }

  fun toByteArray() = hexarray

  fun toInt(littleEndiain: Boolean): Int {
    var byteBuffer = ByteBuffer.allocate(4)
    if (littleEndiain) byteBuffer.order(ByteOrder.LITTLE_ENDIAN)
    for (i in 0 until 4) byteBuffer.put(if (i < hexarray.size) hexarray[i] else 0.toByte())
    byteBuffer.flip()
    return byteBuffer.int
  }

  fun toLong(littleEndiain: Boolean): Long {
    var byteBuffer = ByteBuffer.allocate(8)
    if (littleEndiain) byteBuffer.order(ByteOrder.LITTLE_ENDIAN)
    for (i in 0 until 8) byteBuffer.put(if (i < hexarray.size) hexarray[i] else 0.toByte())
    byteBuffer.flip()
    return byteBuffer.long
  }

  fun toHexString() = createHexstrFromHexarray(hexarray, 0)

  fun toHexString(count: Int) = createHexstrFromHexarray(hexarray, count)

  fun toAsciiString() = createAsciistrFromHexarray(hexarray, 0)

  fun toAsciiString(count: Int) = createAsciistrFromHexarray(hexarray, count)

  private fun createHexarrayFromHexstr(hstr: HexString): ByteArray {
    var hexstr = hstr.toString().replace(" ", "").replace("\r", "").replace("\n", "")
    if (hexstr.isEmpty()) return ByteArray(0)
    require(hexstr.length % 2 == 0) { "format error" }

    var hexarray = ByteArray(hexstr.length / 2)
    for (i in hexstr.indices step 2) hexarray[i / 2] = hexstr.substring(i, i + 2).toInt(16).toByte()
    return hexarray
  }

  private fun createHexstrFromHexarray(hexarray: ByteArray, count: Int): HexString {
    initIntToHexString()
    var stringBuilder = StringBuilder()
    for (i in hexarray.indices) {
      stringBuilder.append(intToHexString[hexarray[i].toInt() and 0xff])
      if (count != 0 && (i + 1) % count == 0) stringBuilder.append("\n")
    }
    return HexString(stringBuilder.toString())
  }

  private fun createAsciistrFromHexarray(hexarray: ByteArray, count: Int): AsciiString {
    initIntToAsciiString()
    var stringBuilder = StringBuilder()
    for (i in hexarray.indices) {
      stringBuilder.append(intToAsciiString[hexarray[i].toInt() and 0xff])
      if (count != 0 && (i + 1) % count == 0) stringBuilder.append("\n")
    }
    return AsciiString(stringBuilder.toString())
  }

  internal fun initIntToHexString() {
    if (intToHexString[255] != null) return
    for (i in 0 until 256) intToHexString[i] = "%02X ".format(i)
  }

  internal fun initIntToAsciiString() {
    if (intToAsciiString[255] != null) return
    for (i in 0 until 256) intToAsciiString[i] =
      if (i < 20 || i > 0x7f) "." else i.toChar().toString()
  }
}
