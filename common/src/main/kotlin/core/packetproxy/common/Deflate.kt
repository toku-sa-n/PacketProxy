/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.common

import java.io.ByteArrayOutputStream
import java.util.zip.DataFormatException
import java.util.zip.Deflater
import java.util.zip.Inflater
import packetproxy.util.Logging.errWithStackTrace

class Deflate {
  fun decompress(data: ByteArray): ByteArray {
    var decompressor = Inflater()
    decompressor.setInput(data)
    var output = ByteArrayOutputStream()
    var result = ByteArray(100000)
    try {
      while (!decompressor.finished()) {
        var length = decompressor.inflate(result)
        if (length > 0) output.write(result, 0, length) else break
      }
    } catch (e: DataFormatException) {
      errWithStackTrace(e)
    }
    return output.toByteArray()
  }

  fun compress(data: ByteArray): ByteArray {
    var compressor = Deflater()
    compressor.setInput(data)
    compressor.finish()
    var output = ByteArrayOutputStream()
    var result = ByteArray(100000)
    while (!compressor.finished()) {
      var length = compressor.deflate(result)
      output.write(result, 0, length)
    }
    return output.toByteArray()
  }
}
