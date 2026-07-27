/*
 * Copyright 2022 DeNA Co., Ltd.
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
package packetproxy.http3.service

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import org.eclipse.jetty.http.MetaData
import org.eclipse.jetty.http3.qpack.QpackEncoder
import org.eclipse.jetty.http3.qpack.QpackException
import org.eclipse.jetty.io.ByteBufferPool
import org.eclipse.jetty.io.MappedByteBufferPool
import packetproxy.http3.utils.readSimpleBytes
import packetproxy.util.Throwing.rethrow

open class Http3HeaderEncoder(capacity: Long) {
  private val bufferPool: ByteBufferPool = MappedByteBufferPool()
  private val lease = ByteBufferPool.Lease(bufferPool)
  private val encoder: QpackEncoder =
    QpackEncoder({ instructions -> instructions.forEach { i -> i.encode(lease) } }, 1024 * 1024)

  init {
    encoder.capacity = capacity.toInt()
  }

  /** エンコーダに命令を入力する Note: エンコーダの内部状態が変化します */
  @Throws(QpackException::class)
  fun putInstructions(instructions: ByteArray) {
    encoder.parseInstructions(ByteBuffer.wrap(instructions))
  }

  /** 現在のデコーダの内部状態を命令化する */
  fun getInstructions(): ByteArray {
    val encoderInsts = ByteArrayOutputStream()
    lease.byteBuffers.forEach(
      rethrow { inst -> encoderInsts.write(readSimpleBytes(inst, inst.remaining().toLong())) }
    )
    return encoderInsts.toByteArray()
  }

  /** ヘッダをエンコードする Note: エンコーダの内部状態が変化します */
  @Throws(QpackException::class)
  fun encode(streamId: Long, metaData: MetaData): ByteArray {
    val buffer = ByteBuffer.allocate(4096)
    encoder.encode(buffer, streamId, metaData)
    buffer.flip()
    return readSimpleBytes(buffer, buffer.remaining().toLong())
  }
}
