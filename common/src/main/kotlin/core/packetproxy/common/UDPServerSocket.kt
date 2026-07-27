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
import java.net.DatagramSocket
import java.util.concurrent.Executors

class UDPServerSocket(port: Int) {
  private val socket = DatagramSocket(port)
  private val connManager = UDPConnManager()

  init {
    createRecvLoop()
  }

  fun close() {
    socket.close()
  }

  fun accept(): Endpoint = connManager.accept()

  private fun createRecvLoop() {
    val executor = Executors.newFixedThreadPool(2)
    executor.submit {
      while (true) {
        val buffer = ByteArray(BUFFER_SIZE)
        val recvPacket = DatagramPacket(buffer, BUFFER_SIZE)
        socket.receive(recvPacket)
        connManager.put(recvPacket)
      }
    }
    executor.submit {
      while (true) {
        socket.send(connManager.get())
      }
    }
  }

  private companion object {
    const val BUFFER_SIZE = 4096
  }
}
