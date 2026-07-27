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
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import javax.net.ssl.SSLSocket
import packetproxy.PrivateDNSClient
import packetproxy.http.Https
import packetproxy.model.CAs.CA
import packetproxy.model.OneShotPacket
import packetproxy.model.Server
import packetproxy.quic.service.connection.ServerConnection
import packetproxy.quic.value.ConnectionIdPair

object EndpointFactory {
  @JvmStatic
  @Throws(Exception::class)
  fun createClientEndpoint(socket: Socket, lookaheadBuffer: InputStream): Endpoint =
    SocketEndpoint(socket, lookaheadBuffer)

  @JvmStatic
  @Throws(Exception::class)
  fun createBothSideSSLEndpoints(
    clientSocket: Socket,
    lookahead: InputStream?,
    serverAddr: InetSocketAddress,
    upstreamProxyAddr: InetSocketAddress?,
    serverName: String,
    ca: CA,
  ): Array<SSLSocketEndpoint> {
    val sslSockets: Array<SSLSocket>
    val endpoints: Array<SSLSocketEndpoint>
    if (upstreamProxyAddr != null) {
      sslSockets =
        Https.createBothSideSSLSockets(
          clientSocket,
          lookahead,
          serverAddr,
          upstreamProxyAddr,
          serverName,
          ca,
        )
      val clientEndpoint = SSLSocketEndpoint(sslSockets[0], serverName)
      val serverEndpoint = SSLSocketEndpoint(sslSockets[1], serverName)
      endpoints = arrayOf(clientEndpoint, serverEndpoint)
    } else {
      sslSockets =
        Https.createBothSideSSLSockets(clientSocket, lookahead, serverAddr, null, serverName, ca)
      val clientEndpoint = SSLSocketEndpoint(sslSockets[0], serverName)
      val serverEndpoint = SSLSocketEndpoint(sslSockets[1], serverName)
      endpoints = arrayOf(clientEndpoint, serverEndpoint)
    }
    return endpoints
  }

  @JvmStatic
  @Throws(Exception::class)
  fun createClientEndpointFromSNIServerName(
    socket: Socket,
    serverName: String,
    ca: CA,
    input: InputStream,
  ): SSLSocketEndpoint {
    val ssl_client = Https.convertToServerSSLSocket(socket, serverName, ca, input)
    return SSLSocketEndpoint(ssl_client, serverName)
  }

  @JvmStatic
  @Throws(Exception::class)
  fun createFromURI(uri: String): Endpoint {
    val u = URI(uri)
    val host = u.host
    val port = if (u.getPort() > 0) u.port else 80
    return if (u.scheme.equals("https", ignoreCase = true)) {
      SSLSocketEndpoint(InetSocketAddress(PrivateDNSClient.getByName(host), port), host, null)
    } else if (u.scheme.equals("http", ignoreCase = true)) {
      SocketEndpoint(InetSocketAddress(PrivateDNSClient.getByName(host), port))
    } else {
      throw Exception(String.format("[Error] Unknown scheme!%s", u.scheme))
    }
  }

  @JvmStatic
  @Throws(Exception::class)
  fun createFromOneShotPacket(packet: OneShotPacket): Endpoint {
    return if (packet.getAlpn() == "h3") {
      // HTTP3 on QUICの場合は特別対応
      ServerConnection(
        ConnectionIdPair.generateRandom(),
        packet.getServerName()!!,
        packet.getServerPort(),
      )
    } else if (packet.getUseSSL()) {
      SSLSocketEndpoint(packet.getServer(), packet.getServerName(), packet.getAlpn())
    } else {
      // nc など複数同時接続を受け付けないconnection用に10秒でtimeoutする
      SocketEndpoint(packet.getServer(), 10 * 1000)
    }
  }

  @JvmStatic
  @Throws(Exception::class)
  fun createFromServer(server: Server): Endpoint {
    return if (server.getUseSSL()) {
      SSLSocketEndpoint(server.getAddress(), server.getIp(), null)
    } else {
      SocketEndpoint(server.getAddress())
    }
  }

  @JvmStatic
  @Throws(Exception::class)
  fun createServerEndpoint(addr: InetSocketAddress): Endpoint = SocketEndpoint(addr)
}
