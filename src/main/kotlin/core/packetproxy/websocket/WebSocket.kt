/*
 * Copyright 2019,2023 DeNA Co., Ltd.
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
package packetproxy.websocket

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.LinkedList

class WebSocket {
  private var frames = LinkedList<WebSocketFrame>()

  /** Last opcode from [frameAvailable]; used when re-encoding the payload to a wire frame. */
  private var lastDequeuedOpCode: OpCode? = OpCode.Binary

  @Throws(Exception::class)
  fun frameArrived(data: ByteArray) {
    val buffer = ByteBuffer.wrap(data)
    val frame = WebSocketFrame.parse(buffer)
    frames.add(frame)
    if (buffer.remaining() > 0) {
      throw Exception("WebSocket: packet data is remaining.")
    }
  }

  @Throws(Exception::class)
  fun passThroughFrame(): ByteArray {
    val passBytes = ByteArrayOutputStream()
    val iterator = frames.iterator()
    while (iterator.hasNext()) {
      val frame = iterator.next()
      if (frame.opcode == OpCode.Text || frame.opcode == OpCode.Binary) {
        continue
      }
      passBytes.write(frame.getBytes())
      iterator.remove()
    }
    return passBytes.toByteArray()
  }

  @Throws(Exception::class)
  fun frameAvailable(): ByteArray? {
    val frame = frames.pollFirst() ?: return null
    lastDequeuedOpCode = frame.opcode
    return frame.payload
  }

  /**
   * Opcode of the frame most recently returned from [frameAvailable]. Encode paths use this to
   * preserve Text vs Binary when rebuilding WebSocket frames.
   */
  fun lastDequeuedOpCode(): OpCode? = lastDequeuedOpCode

  companion object {
    @JvmStatic fun checkDelimiter(data: ByteArray): Int = WebSocketFrame.checkDelimiter(data)
  }
}
