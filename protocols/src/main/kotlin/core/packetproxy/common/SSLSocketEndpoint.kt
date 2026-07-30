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
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import packetproxy.http.Https

open class SSLSocketEndpoint : Endpoint {
  @JvmField protected var socket: SSLSocket
  @JvmField protected var server_name: String?
  @JvmField protected var alpn: String? = null

  constructor(ep: SSLSocketEndpoint) {
    server_name = ep.server_name
    socket = ep.socket
    alpn = ep.alpn
  }

  constructor(socket: SSLSocket, SNIServerName: String?) {
    server_name = SNIServerName
    this.socket = socket
    alpn = socket.applicationProtocol
  }

  @Throws(Exception::class)
  constructor(https: Https, addr: InetSocketAddress, SNIServerName: String?, alpn: String?) {
    server_name = SNIServerName
    this.alpn = alpn
    socket = https.createClientSSLSocket(addr, SNIServerName, alpn)
  }

  @Throws(Exception::class) override fun getInputStream(): InputStream = socket.getInputStream()

  @Throws(Exception::class) override fun getOutputStream(): OutputStream = socket.getOutputStream()

  override fun getAddress(): InetSocketAddress =
    InetSocketAddress(socket.inetAddress, socket.getPort())

  override fun getLocalPort(): Int = socket.localPort

  override fun getName(): String? = server_name

  override fun getSocket(): Socket = socket

  open fun getApplicationProtocol(): String? = socket.applicationProtocol
}
