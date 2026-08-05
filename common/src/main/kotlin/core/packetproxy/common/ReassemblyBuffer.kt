/*
 * Copyright 2026 DeNA Co., Ltd.
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

/**
 * Growable byte buffer with a discarded-prefix offset to avoid rewriting the unconsumed tail on
 * every packet boundary check.
 */
class ReassemblyBuffer(private val maxSize: Int = DEFAULT_MAX_SIZE) {
  private var buf = ByteArray(INITIAL_CAPACITY)
  private var start = 0
  private var end = 0

  fun size(): Int = end - start

  fun isEmpty(): Boolean = start >= end

  fun write(data: ByteArray, off: Int, len: Int) {
    if (len <= 0) {
      return
    }
    val newSize = size() + len
    if (newSize > maxSize) {
      throw IllegalStateException("reassembly buffer exceeded max size: $maxSize")
    }
    ensureCapacity(newSize)
    if (end + len > buf.size) {
      compact()
    }
    System.arraycopy(data, off, buf, end, len)
    end += len
  }

  fun toByteArray(): ByteArray {
    if (isEmpty()) {
      return byteArrayOf()
    }
    return buf.copyOfRange(start, end)
  }

  fun discard(n: Int) {
    if (n <= 0) {
      return
    }
    start += n
    if (start >= end) {
      start = 0
      end = 0
      return
    }
    if (start > INITIAL_CAPACITY && start > buf.size / 2) {
      compact()
    }
  }

  private fun ensureCapacity(needed: Int) {
    if (needed <= buf.size) {
      return
    }
    var capacity = buf.size
    while (capacity < needed) {
      capacity = (capacity * 2).coerceAtMost(maxSize)
      if (capacity < needed && capacity == maxSize) {
        break
      }
    }
    if (capacity < needed) {
      throw IllegalStateException("reassembly buffer exceeded max size: $maxSize")
    }
    val next = ByteArray(capacity)
    val sz = size()
    if (sz > 0) {
      System.arraycopy(buf, start, next, 0, sz)
    }
    buf = next
    start = 0
    end = sz
  }

  private fun compact() {
    val sz = size()
    if (sz > 0 && start > 0) {
      System.arraycopy(buf, start, buf, 0, sz)
    }
    start = 0
    end = sz
  }

  companion object {
    const val DEFAULT_MAX_SIZE = 64 * 1024 * 1024
    private const val INITIAL_CAPACITY = 64 * 1024
  }
}
