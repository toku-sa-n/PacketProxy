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
package packetproxy.common

import org.apache.commons.lang3.ArrayUtils
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class BinaryBuffer {
  private var buffer_capacity = 4096
  private var buffer = ByteArray(buffer_capacity)
  private var data_size = 0
  private var data_size_in_utf8 = 0

  constructor()

  @Throws(Exception::class)
  constructor(input: ByteArray) {
    insert(0, input)
  }

  override fun toString(): String {
    try {
      return String.format(
        "capacity: %d, data: %d, data_utf8: %d\n",
        buffer_capacity,
        data_size,
        data_size_in_utf8,
      )
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    return ""
  }

  fun toByteArray(): ByteArray = ArrayUtils.subarray(buffer, 0, data_size)

  @Throws(Exception::class)
  fun reset(input: ByteArray) {
    removeAll()
    insert(0, input)
  }

  fun getLength(): Int = data_size

  fun getLengthInUTF8(): Int = data_size_in_utf8

  fun removeAll() {
    data_size = 0
    data_size_in_utf8 = 0
  }

  fun remove(index: Int, length: Int) {
    var removeLength = length
    if (data_size < index + removeLength) {
      log("[Error] Something wrong (%d < %d + %d)", data_size, index, removeLength)
      return
    }
    data_size_in_utf8 -= String(buffer, index, removeLength).length
    System.arraycopy(buffer, index + removeLength, buffer, index, data_size - index - removeLength)
    data_size -= removeLength
  }

  @Throws(Exception::class)
  fun insert(index: Int, input: ByteArray?) {
    if (input == null) return
    if (data_size + input.size > buffer_capacity) {
      expandBuffer(data_size + input.size)
    }
    System.arraycopy(buffer, index, buffer, index + input.size, data_size - index)
    System.arraycopy(input, 0, buffer, index, input.size)
    data_size += input.size
    data_size_in_utf8 += String(input).length
  }

  private fun expandBuffer(n: Int) {
    if (n < buffer_capacity) return

    var new_buffer_capacity = buffer_capacity
    while (new_buffer_capacity < n) {
      new_buffer_capacity *= 2
    }

    val new_buffer = ByteArray(new_buffer_capacity)
    System.arraycopy(buffer, 0, new_buffer, 0, buffer_capacity)

    buffer = new_buffer
    buffer_capacity = new_buffer_capacity
  }
}
