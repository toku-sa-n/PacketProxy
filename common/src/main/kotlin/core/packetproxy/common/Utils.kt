/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.common

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.tools.ToolProvider
import org.apache.commons.codec.binary.Base64
import org.apache.commons.lang3.ArrayUtils
import packetproxy.util.err

class Utils {
  enum class Platform {
    WINDOWS,
    MAC,
    LINUX,
  }

  companion object {
    @JvmStatic
    fun splitArray(array: ByteArray, maxSubArraySize: Int): List<ByteArray> {
      var list = ArrayList<ByteArray>()
      var position = 0
      while (position < array.size) {
        var subArraySize = minOf(array.size - position, maxSubArraySize)
        list.add(ArrayUtils.subarray(array, position, position + subArraySize))
        position += subArraySize
      }
      return list
    }

    @JvmStatic
    fun indexOf(inputData: ByteArray, startIdx: Int, endIdx: Int, word: ByteArray): Int {
      assert(endIdx <= inputData.size)
      for (i in startIdx + word.size - 1 until endIdx) {
        var startInputIdx = i - word.size + 1
        var wordIdx = 0
        while (wordIdx < word.size && startInputIdx + wordIdx < inputData.size) {
          if (word[wordIdx] != inputData[startInputIdx + wordIdx]) break
          wordIdx++
        }
        if (wordIdx == word.size) return startInputIdx
      }
      return -1
    }

    @JvmStatic
    fun checkOS(): Platform =
      when {
        System.getProperty("os.name").contains("Windows") -> Platform.WINDOWS
        System.getProperty("os.name").contains("Mac") -> Platform.MAC
        else -> Platform.LINUX
      }

    @JvmStatic fun isWindows() = checkOS() == Platform.WINDOWS

    @JvmStatic fun isMac() = checkOS() == Platform.MAC

    @JvmStatic
    fun executeCmd(vararg command: String): ByteArray = execute(toCmdArray(*command), true)

    @JvmStatic
    fun executeExe(vararg command: String): ByteArray = execute(addMonoPath(*command), true)

    @JvmStatic
    fun executeRuby(vararg command: String): ByteArray =
      Base64.decodeBase64(execute(addRubyPath(*command), false))

    @JvmStatic
    fun readfile(filename: String): ByteArray {
      FileInputStream(filename).use { fileInputStream ->
        BufferedInputStream(fileInputStream).use { input ->
          var output = ByteArrayOutputStream()
          var buffer = ByteArray(4096)
          var length: Int
          while (input.read(buffer, 0, 4096).also { length = it } > 0) output.write(
            buffer,
            0,
            length,
          )
          return output.toByteArray()
        }
      }
    }

    @JvmStatic
    fun deletefile(filename: String) {
      var file = File(filename)
      if (file.exists()) file.delete()
    }

    @JvmStatic
    fun writefile(filename: String, data: ByteArray) {
      BufferedOutputStream(FileOutputStream(filename)).use { output ->
        output.write(data)
        output.flush()
      }
    }

    @JvmStatic
    fun gzip(src: ByteArray): ByteArray {
      var output = ByteArrayOutputStream()
      GZIPOutputStream(output).use { gzipOutput ->
        gzipOutput.write(src)
        gzipOutput.flush()
        gzipOutput.finish()
      }
      return output.toByteArray()
    }

    @JvmStatic
    fun ungzip(src: ByteArray): ByteArray {
      var output = ByteArrayOutputStream()
      GZIPInputStream(ByteArrayInputStream(src)).use { gzipInput ->
        var buffer = ByteArray(1024)
        while (true) {
          var length = gzipInput.read(buffer)
          if (length < 0) break
          output.write(buffer, 0, length)
        }
      }
      return output.toByteArray()
    }

    @JvmStatic
    fun replaceArray(src: ByteArray, area: Range, replacer: ByteArray) =
      replaceArray(src, area.positionStart, area.positionEnd, replacer)

    @JvmStatic
    fun replaceArray(src: ByteArray, startIdx: Int, endIdx: Int, replacer: ByteArray): ByteArray {
      var head = ArrayUtils.subarray(src, 0, startIdx)
      var tail = ArrayUtils.subarray(src, endIdx, src.size)
      return head + replacer + tail
    }

    @JvmStatic
    fun replaceBinary(data: ByteArray, binPattern: ByteArray, binReplaced: ByteArray): ByteArray {
      var result = data
      var index = 0
      while (index < result.size) {
        index = indexOf(result, index, result.size, binPattern)
        if (index < 0) return result
        var frontData = ArrayUtils.subarray(result, 0, index)
        var backData = ArrayUtils.subarray(result, index + binPattern.size, result.size)
        result = frontData + binReplaced
        result += backData
        index += binReplaced.size
      }
      return result
    }

    @JvmStatic
    fun getSelectedCharacters(src: ByteArray, startIdx: Int, endIdx: Int) =
      ArrayUtils.subarray(src, startIdx, endIdx)

    @JvmStatic
    fun isPrintable(data: ByteArray): Boolean {
      for (byte in data) if (byte < 32.toByte() || byte > 126.toByte()) return false
      return true
    }

    @JvmStatic fun supportedJava() = executedByJDK()

    @JvmStatic fun executedByJDK() = ToolProvider.getSystemJavaCompiler() != null

    @JvmStatic
    fun javaVersionIs1_8() = System.getProperty("java.version").matches(Regex("1\\.8\\..*"))

    private fun addMonoPath(vararg args: String): Array<String> =
      buildList {
          if (checkOS() == Platform.MAC || checkOS() == Platform.LINUX) add("mono")
          addAll(args)
        }
        .toTypedArray()

    private fun toCmdArray(vararg args: String): Array<String> = arrayOf(*args)

    private fun addRubyPath(vararg args: String): Array<String> =
      buildList {
          if (checkOS() == Platform.MAC || checkOS() == Platform.LINUX) add("ruby")
          addAll(args)
        }
        .toTypedArray()

    private fun execute(command: Array<String>, logError: Boolean): ByteArray {
      var process = Runtime.getRuntime().exec(command)
      var output = ByteArrayOutputStream()
      var buffer = ByteArray(4096)
      var length: Int
      process.inputStream.use { input ->
        while (input.read(buffer, 0, 4096).also { length = it } > 0) output.write(buffer, 0, length)
      }
      if (logError) {
        var errorOutput = ByteArrayOutputStream()
        process.errorStream.use { errorStream ->
          while (errorStream.read(buffer, 0, 4096).also { length = it } > 0) errorOutput.write(
            buffer,
            0,
            length,
          )
        }
        if (errorOutput.size() > 0) err(errorOutput.toString(Charsets.UTF_8.name()))
      } else {
        // Drain stderr to avoid process hang even when not logging.
        process.errorStream.use { errorStream ->
          while (errorStream.read(buffer, 0, 4096).also { length = it } > 0) {
            // discard
          }
        }
      }
      process.waitFor()
      return output.toByteArray()
    }
  }
}
