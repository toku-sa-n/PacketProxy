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

import java.net.DatagramPacket
import java.net.InetSocketAddress
import java.util.concurrent.BlockingQueue
import java.util.concurrent.Executors
import org.apache.commons.io.output.ByteArrayOutputStream

class UDPConn(private val addr: InetSocketAddress) {
  private val pipe = PipeEndpoint(addr)

  fun put(data: ByteArray, offset: Int, length: Int) {
    val output = ByteArrayOutputStream()
    output.write(data, offset, length)
    put(output.toByteArray())
    output.close()
  }

  fun put(data: ByteArray) {
    val output = pipe.getRawEndpoint().getOutputStream()
    output.write(data)
    output.flush()
  }

  fun getAutomatically(queue: BlockingQueue<DatagramPacket>) {
    val executor = Executors.newSingleThreadExecutor()
    executor.submit {
      while (true) {
        val input = pipe.getRawEndpoint().getInputStream()
        val buffer = ByteArray(BUFFER_SIZE)
        val length = input.read(buffer)
        queue.put(DatagramPacket(buffer, length, addr))
      }
    }
  }

  fun getEndpoint(): Endpoint = pipe.getProxyRawEndpoint()

  private companion object {
    const val BUFFER_SIZE = 4096
  }
}
