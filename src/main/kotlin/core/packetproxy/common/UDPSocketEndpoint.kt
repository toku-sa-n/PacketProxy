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

import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.Executors

class UDPSocketEndpoint(addr: InetSocketAddress) : Endpoint {
  private val socket = DatagramSocket()
  private val serverAddr = addr
  private val pipe = PipeEndpoint(addr)

  init {
    socket.connect(addr)
    loop()
  }

  override fun getAddress(): InetSocketAddress = serverAddr

  override fun getInputStream(): InputStream = pipe.getProxyRawEndpoint().getInputStream()

  override fun getOutputStream(): OutputStream = pipe.getProxyRawEndpoint().getOutputStream()

  override fun getLocalPort(): Int = socket.localPort

  override fun getName(): String? = null

  private fun loop() {
    val executor = Executors.newFixedThreadPool(2)
    executor.submit {
      while (true) {
        val input = pipe.getRawEndpoint().getInputStream()
        val inputData = ByteArray(BUFFER_SIZE)
        val length = input.read(inputData)
        socket.send(DatagramPacket(inputData, 0, length, serverAddr))
      }
    }
    executor.submit {
      while (true) {
        val buffer = ByteArray(BUFFER_SIZE)
        val recvPacket = DatagramPacket(buffer, BUFFER_SIZE)
        socket.receive(recvPacket)
        val output = pipe.getRawEndpoint().getOutputStream()
        output.write(recvPacket.getData(), 0, recvPacket.length)
        output.flush()
      }
    }
  }

  private companion object {
    const val BUFFER_SIZE = 4096
  }
}
