/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.common

class Hex {
  fun encode(raw: ByteArray?): ByteArray {
    requireNotNull(raw)
    var output = ByteArray(raw.size * 2)
    for (i in raw.indices) {
      var nibble1 = (raw[i].toInt() shr 4) and 0x0f
      var nibble2 = raw[i].toInt() and 0x0f
      nibble1 += 0x30
      nibble2 += 0x30
      nibble1 += (nibble1 - 0x30) / 10 * 39
      nibble2 += (nibble2 - 0x30) / 10 * 39
      output[2 * i] = nibble1.toByte()
      output[2 * i + 1] = nibble2.toByte()
    }
    return output
  }

  fun decode(encoded: ByteArray?): ByteArray {
    require(encoded != null && (encoded.size and 0x01) == 0)
    var output = ByteArray(encoded.size shr 1)
    for (i in encoded.indices step 2) {
      var nibble1 = encoded[i].toInt() and 0x00ff
      var nibble2 = encoded[i + 1].toInt() and 0x00ff
      nibble1 -= nibble1 / 0x60 * 32
      nibble2 -= nibble2 / 0x60 * 32
      nibble1 -= nibble1 / 0x40 * 7
      nibble2 -= nibble2 / 0x40 * 7
      nibble1 -= 0x30
      nibble2 -= 0x30
      nibble1 = nibble1 shl 4
      output[i shr 1] = (nibble1 or nibble2).toByte()
    }
    return output
  }

  companion object {
    @JvmStatic
    fun isHexString(hexStr: String): Boolean {
      for (byte in hexStr.toByteArray()) {
        var character = byte.toInt() and 0x00ff
        if (character !in 0x30..0x39 && character !in 0x41..0x46 && character !in 0x61..0x66)
          return false
      }
      return true
    }
  }
}
