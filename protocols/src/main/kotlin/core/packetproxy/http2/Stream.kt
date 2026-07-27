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
package packetproxy.http2

import java.io.ByteArrayOutputStream
import java.util.LinkedList
import packetproxy.http2.frames.Frame

open class Stream {
  private val stream: MutableList<Frame> = LinkedList()

  fun write(frame: Frame) {
    stream.add(frame)
  }

  @Throws(Exception::class)
  fun toByteArray(): ByteArray {
    val out = ByteArrayOutputStream()
    for (frame in stream) {
      out.write(frame.toByteArray())
    }
    return out.toByteArray()
  }

  @Throws(Exception::class)
  fun toByteArrayWithoutExtra(): ByteArray {
    val out = ByteArrayOutputStream()
    for (frame in stream) {
      out.write(frame.toByteArrayWithoutExtra())
    }
    return out.toByteArray()
  }

  @Throws(Exception::class)
  fun payloadSize(): Int {
    var size = 0
    for (frame in stream) {
      size += frame.length
    }
    return size
  }
}
