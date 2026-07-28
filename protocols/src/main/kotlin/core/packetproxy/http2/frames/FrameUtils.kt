@file:JvmName("FrameUtils")

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
package packetproxy.http2.frames

import java.io.ByteArrayOutputStream
import java.util.Arrays
import java.util.LinkedList
import org.apache.commons.codec.binary.Hex
import org.apache.commons.lang3.ArrayUtils
import org.eclipse.jetty.http2.hpack.HpackDecoder
import packetproxy.util.errWithStackTrace

var PREFACE: ByteArray = byteArrayOf()
var SETTINGS: ByteArray = byteArrayOf()
var END_SETTINGS: ByteArray = byteArrayOf()
var WINDOW_UPDATE: ByteArray = byteArrayOf()

private val initialized = run {
  try {
    PREFACE = Hex.decodeHex("505249202a20485454502f322e300d0a0d0a534d0d0a0d0a".toCharArray())
    SETTINGS =
      Hex.decodeHex(
        "0000180400000000000001000010000003000003e800045fffffff000200000000".toCharArray()
      )
    END_SETTINGS = Hex.decodeHex("000000040100000000".toCharArray())
    WINDOW_UPDATE = Hex.decodeHex("0000040800000000005fffffff".toCharArray())
  } catch (e: Exception) {
    errWithStackTrace(e)
  }
  true
}

fun isPreface(frameData: ByteArray): Boolean =
  if (PREFACE.size > frameData.size) false
  else Arrays.equals(frameData, 0, PREFACE.size, PREFACE, 0, PREFACE.size)

@Throws(Exception::class)
fun checkDelimiter(data: ByteArray): Int {
  if (data.size < 9) return -1
  if (isPreface(data)) return PREFACE.size
  val headerSize = 9
  val payloadSize =
    ((data[0].toInt() and 0xff) shl
      16 or
      ((data[1].toInt() and 0xff) shl 8) or
      (data[2].toInt() and 0xff))
  val expectedSize = headerSize + payloadSize
  if (data.size < expectedSize) return -1
  return expectedSize
}

@Throws(Exception::class)
fun toByteArray(frames: List<Frame>): ByteArray {
  val out = ByteArrayOutputStream()
  for (frame in frames) out.write(frame.toByteArray())
  return out.toByteArray()
}

@Throws(Exception::class)
fun parseFrames(frames: ByteArray): List<Frame> = parseFrames(frames, null)

@Throws(Exception::class)
fun parseFrames(framesIn: ByteArray?, hpackDecoder: HpackDecoder?): List<Frame> {
  val frameList: MutableList<Frame> = LinkedList()
  var frames = framesIn
  while (frames != null && frames.isNotEmpty()) {
    val delim = checkDelimiter(frames)
    val frame = ArrayUtils.subarray(frames, 0, delim)
    frames = ArrayUtils.subarray(frames, delim, frames.size)
    if (!isPreface(frame)) frameList.add(create(frame, hpackDecoder))
  }
  return frameList
}
