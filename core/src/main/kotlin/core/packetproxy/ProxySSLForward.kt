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
package packetproxy

import java.net.ServerSocket
import java.net.Socket
import packetproxy.common.EndpointFactory
import packetproxy.common.SSLSocketEndpoint
import packetproxy.common.SocketEndpoint
import packetproxy.encode.EncodeHTTPBase
import packetproxy.model.ListenPort
import packetproxy.model.SSLPassThroughs
import packetproxy.model.Server
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.Logging.log

class ProxySSLForward(
  private val listen_socket: ServerSocket,
  private val listen_info: ListenPort,
) : Proxy() {
  override fun run() {
    val clients = ArrayList<Socket>()
    while (!listen_socket.isClosed) {
      try {
        val client = listen_socket.accept()
        clients.add(client)
        log("[SSLForward] accept")
        checkSSLForward(client)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    for (sc in clients) {
      try {
        sc.close()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  @Throws(Exception::class)
  private fun checkSSLForward(client: Socket) {
    val server = listen_info.getServer()!!
    val serverAddr = server.getAddress()
    if (SSLPassThroughs.getInstance().includes(server.getIp()!!, listen_info.getPort())) {
      val server_e = SocketEndpoint(serverAddr)
      val client_e = SocketEndpoint(client)
      val duplex = DuplexAsync(client_e, server_e)
      duplex.start()
    } else {
      val eps =
        EndpointFactory.createBothSideSSLEndpoints(
          client,
          null,
          serverAddr,
          null,
          listen_info.getServer()!!.getIp()!!,
          listen_info.getCA().get(),
        )
      createConnection(eps[0], eps[1], listen_info.getServer())
    }
  }

  @Throws(Exception::class)
  fun createConnection(client_e: SSLSocketEndpoint, server_e: SSLSocketEndpoint, server: Server?) {
    var duplex: DuplexAsync? = null
    var alpn = client_e.getApplicationProtocol()
    if (server == null) {
      duplex =
        if (alpn == "h2" || alpn == "http/1.1" || alpn == "http/1.0") {
          DuplexFactory.createDuplexAsync(client_e, server_e, "HTTP", alpn)
        } else {
          DuplexFactory.createDuplexAsync(client_e, server_e, "Sample", alpn)
        }
    } else {
      if (alpn.isNullOrEmpty()) {
        val encoder = EncoderManager.getInstance().createInstance(server.getEncoder()!!, "")
        if (encoder is EncodeHTTPBase) {
          /* The client does not support ALPN. It seems to be an old HTTP client */
          alpn = "http/1.1"
        }
      }
      duplex = DuplexFactory.createDuplexAsync(client_e, server_e, server.getEncoder()!!, alpn)
    }
    duplex.start()
    DuplexManager.getInstance().registerDuplex(duplex)
  }

  @Throws(Exception::class)
  override fun close() {
    listen_socket.close()
  }
}
