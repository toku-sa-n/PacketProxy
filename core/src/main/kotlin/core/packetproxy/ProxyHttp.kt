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
import packetproxy.Simplex.SimplexEventAdapter
import packetproxy.common.Endpoint
import packetproxy.common.EndpointFactory
import packetproxy.common.SSLSocketEndpoint
import packetproxy.common.SocketEndpoint
import packetproxy.http.Http
import packetproxy.http.Https
import packetproxy.model.ListenPort
import packetproxy.model.ModelServices
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class ProxyHttp
@Throws(Exception::class)
constructor(
  private val listen_socket: ServerSocket,
  private val listen_info: ListenPort,
  private val duplexFactory: DuplexFactory,
  private val endpointFactory: EndpointFactory,
  private val modelServices: ModelServices,
  private val https: Https,
) : Proxy() {
  override fun run() {
    val clients = ArrayList<Socket>()
    while (!listen_socket.isClosed) {
      try {
        val client = listen_socket.accept()
        clients.add(client)
        log("accept")

        val client_loopback = Simplex(client.inputStream, client.outputStream)

        client_loopback.addSimplexEventListener(
          object : SimplexEventAdapter() {
            @Throws(Exception::class)
            override fun onPacketReceived(data: ByteArray): Int = Http.parseHttpDelimiter(data)

            @Throws(Exception::class)
            override fun onChunkReceived(data: ByteArray): ByteArray {
              var result = ByteArray(0)
              synchronized(client_loopback) {
                val http = Http.create(data, modelServices.resolutions)

                if (http.method == "CONNECT") {
                  // HTTP2対応の都合上、ALPNを早期に確定する必要がある。
                  // そのため、早めに「connection established」を返すことで、早めにSSLハンドシェイクを実施できるよう準備する。
                  client_loopback.sendWithoutRecording(
                    "HTTP/1.0 200 Connection Established\r\n\r\n".toByteArray()
                  )

                  var serverName = http.serverName
                  if (serverName.matches(Regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"))) {
                    serverName = https.getCommonName(http.serverAddr)
                    log("Overwrite CN: %s --> %s", http.serverName, serverName)
                  }

                  if (modelServices.sslPassThroughs.includes(serverName, listen_info.getPort())) {
                    val server_e = SocketEndpoint(http.serverAddr)
                    val client_e = SocketEndpoint(client)
                    val d = DuplexAsync(client_e, server_e)
                    d.start()
                  } else {
                    val clientE: SSLSocketEndpoint
                    val serverE: SSLSocketEndpoint
                    if (
                      listen_info.getServer(modelServices.database) != null
                    ) { // upstream proxyに接続する時
                      val es =
                        endpointFactory.createBothSideSSLEndpoints(
                          client,
                          null,
                          http.serverAddr,
                          listen_info
                            .getServer(modelServices.database)!!
                            .getAddress(modelServices.resolutions),
                          http.serverName,
                          listen_info.getCA().get(),
                        )
                      clientE = es[0]
                      serverE = es[1]
                    } else { // 直接サーバに接続する時
                      val es =
                        endpointFactory.createBothSideSSLEndpoints(
                          client,
                          null,
                          http.serverAddr,
                          null,
                          http.serverName,
                          listen_info.getCA().get(),
                        )
                      clientE = es[0]
                      serverE = es[1]
                    }
                    var ALPN = clientE.getApplicationProtocol()
                    if (ALPN.isNullOrEmpty()) {
                      /* The client does not support ALPN. It seems to be an old HTTP client */
                      ALPN = "http/1.1"
                    }
                    val serverSetting = modelServices.servers.queryByAddress(http.serverAddr)
                    val encoderName = serverSetting?.getEncoder() ?: "HTTP"
                    val d = duplexFactory.createDuplexAsync(clientE, serverE, encoderName, ALPN)
                    d.start()
                  }

                  client_loopback.finishWithoutClose()
                } else if (http.isProxy) {
                  val client_e = SocketEndpoint(client)
                  val next = listen_info.getServer(modelServices.database)
                  val server_e: Endpoint

                  if (next != null) { // connect to upstream proxy
                    server_e = SocketEndpoint(next.getAddress(modelServices.resolutions))
                  } else {
                    http.disableProxyFormatUrl() // direct connect!
                    val s = modelServices.servers.queryByAddress(http.serverAddr)
                    server_e =
                      if (s != null) {
                        endpointFactory.createFromServer(s)
                      } else {
                        SocketEndpoint(http.serverAddr)
                      }
                  }

                  var flag_keepalive = false
                  if (http.header.getAllValue("Connection").contains("keep-alive")) {
                    flag_keepalive = true
                  }
                  http.header.update("Connection", "close")
                  http.header.removeAll("Proxy-Connection")

                  val response =
                    Http.create(createConnection(client_e, server_e, http.toByteArray()))

                  if (
                    response.header.getAllValue("Connection").contains("keep-alive") &&
                      flag_keepalive
                  ) {
                    response.header.update("Connection", "keep-alive")
                    response.header.update("Proxy-Connection", "keep-alive")
                  } else {
                    response.header.update("Connection", "close")
                    response.header.update("Proxy-Connection", "close")
                    client_loopback.close()
                  }
                  result = response.toByteArray()
                }
              }
              return result
            }
          }
        )
        client_loopback.start()
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
  override fun close() {
    listen_socket.close()
  }

  @Throws(Exception::class)
  private fun createConnection(
    client: Endpoint,
    server: Endpoint,
    input_data: ByteArray,
  ): ByteArray {
    val s = modelServices.servers.queryByAddress(server.getAddress())
    val duplex =
      if (s != null) {
        duplexFactory.createDuplexSync(client, server, s.getEncoder()!!, "http/1.1")
      } else {
        duplexFactory.createDuplexSync(client, server, "HTTP", "http/1.1")
      }
    duplex.send(input_data)
    val output_data = duplex.receive()
    duplex.close()
    return output_data!!
  }
}
