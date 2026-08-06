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
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class UDPServerSocket(port: Int) {
  private val socket = DatagramSocket(port)
  private val connManager = UDPConnManager()
  private val executor: ExecutorService = Executors.newFixedThreadPool(2)

  init {
    createRecvLoop()
  }

  fun close() {
    executor.shutdownNow()
    try {
      executor.awaitTermination(2, TimeUnit.SECONDS)
    } catch (_: InterruptedException) {
      Thread.currentThread().interrupt()
    }
    socket.close()
  }

  fun accept(): Endpoint = connManager.accept()

  private fun createRecvLoop() {
    executor.submit {
      while (!socket.isClosed && !Thread.currentThread().isInterrupted) {
        try {
          val buffer = ByteArray(BUFFER_SIZE)
          val recvPacket = DatagramPacket(buffer, BUFFER_SIZE)
          socket.receive(recvPacket)
          connManager.put(recvPacket)
        } catch (_: Exception) {
          if (socket.isClosed) break
        }
      }
    }
    executor.submit {
      while (!socket.isClosed && !Thread.currentThread().isInterrupted) {
        try {
          socket.send(connManager.get())
        } catch (_: Exception) {
          if (socket.isClosed) break
        }
      }
    }
  }

  private companion object {
    // UDP theoretical max payload is 65507; use full DatagramPacket capacity.
    const val BUFFER_SIZE = 65535
  }
}
