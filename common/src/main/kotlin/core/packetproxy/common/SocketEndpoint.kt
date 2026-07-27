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
import java.io.SequenceInputStream
import java.net.InetSocketAddress
import java.net.Socket

class SocketEndpoint : Endpoint {
  internal val socket: Socket
  private val inputstream: InputStream

  constructor(socket: Socket) {
    this.socket = socket
    inputstream = socket.getInputStream()
  }

  constructor(socket: Socket, lookaheadBuffer: InputStream) {
    this.socket = socket
    inputstream = SequenceInputStream(lookaheadBuffer, socket.getInputStream())
  }

  constructor(addr: InetSocketAddress) {
    socket = Socket()
    socket.connect(addr)
    inputstream = socket.getInputStream()
  }

  constructor(addr: InetSocketAddress, timeout: Int) {
    socket = Socket()
    socket.connect(addr, timeout)
    inputstream = socket.getInputStream()
  }

  override fun getAddress(): InetSocketAddress =
    InetSocketAddress(socket.inetAddress, socket.getPort())

  override fun getInputStream(): InputStream = inputstream

  override fun getOutputStream(): OutputStream = socket.getOutputStream()

  override fun getLocalPort(): Int = socket.localPort

  override fun getName(): String? = null
}
