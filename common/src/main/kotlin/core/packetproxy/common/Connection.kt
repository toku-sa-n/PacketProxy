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

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

class Connection {
  enum class Direction {
    NO_DIRECTION,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
  }

  private var listen_port: Int
  private var proxy_port: Int
  private var client: InetSocketAddress?
  private var server: InetSocketAddress?
  private var direction: Direction

  constructor() {
    listen_port = 0
    proxy_port = 0
    client = InetSocketAddress(0)
    server = InetSocketAddress(0)
    direction = Direction.NO_DIRECTION
  }

  constructor(
    listen_port: Int,
    proxy_port: Int,
    client: InetSocketAddress?,
    server: InetSocketAddress?,
    direction: Direction,
  ) {
    this.listen_port = listen_port
    this.proxy_port = proxy_port
    this.client = client
    this.server = server
    this.direction = direction
  }

  constructor(
    listen_port: Int,
    proxy_port: Int,
    client: InetSocketAddress?,
    server: InetSocketAddress?,
  ) {
    this.listen_port = listen_port
    this.proxy_port = proxy_port
    this.client = client
    this.server = server
    this.direction = Direction.NO_DIRECTION
  }

  constructor(
    listen_port: Int,
    client_socket: Socket?,
    server_socket: Socket?,
    direction: Direction,
  ) {
    var client_addr: InetSocketAddress? = null
    var server_addr: InetSocketAddress? = null
    var proxy_port = 0

    if (client_socket != null) {
      val client_ip = client_socket.inetAddress
      val client_port = client_socket.port
      client_addr = InetSocketAddress(client_ip, client_port)
    }
    if (server_socket != null) {
      val server_ip = server_socket.inetAddress
      val server_port = server_socket.port
      server_addr = InetSocketAddress(server_ip, server_port)
      proxy_port = server_socket.localPort
    }

    this.listen_port = listen_port
    this.proxy_port = proxy_port
    this.client = client_addr
    this.server = server_addr
    this.direction = direction
  }

  fun getListenPort(): Int = listen_port

  fun getProxyPort(): Int = proxy_port

  fun getClientIP(): InetAddress? = client?.address

  fun getClientPort(): Int = client?.getPort() ?: 0

  fun getServerIP(): InetAddress? = server?.address

  fun getServerPort(): Int = server?.getPort() ?: 0

  fun getClient(): InetSocketAddress? = client

  fun getServer(): InetSocketAddress? = server

  fun getDestination(): InetSocketAddress? =
    if (direction == Direction.CLIENT_TO_SERVER) server else client

  fun getSource(): InetSocketAddress? =
    if (direction == Direction.CLIENT_TO_SERVER) client else server

  fun getDirection(): Direction = direction

  override fun equals(other: Any?): Boolean {
    if (other !is Connection) {
      return false
    }
    val conn = other
    if (
      listen_port != conn.listen_port ||
        client != conn.getClient() ||
        server != conn.getServer() ||
        direction != conn.getDirection()
    ) {
      return false
    }
    return true
  }

  override fun hashCode(): Int {
    var result = listen_port
    result = 31 * result + proxy_port
    result = 31 * result + (client?.hashCode() ?: 0)
    result = 31 * result + (server?.hashCode() ?: 0)
    result = 31 * result + direction.hashCode()
    return result
  }
}
