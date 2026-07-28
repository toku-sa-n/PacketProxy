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
import packetproxy.common.Endpoint
import packetproxy.common.EndpointFactory
import packetproxy.common.SocketEndpoint
import packetproxy.model.Database
import packetproxy.model.ListenPort
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class ProxyForward(
  private val listen_socket: ServerSocket,
  private val listen_info: ListenPort,
  private val duplexFactory: DuplexFactory,
  private val duplexManager: DuplexManager,
  private val endpointFactory: EndpointFactory,
  private val database: Database,
) : Proxy() {
  override fun run() {
    while (!listen_socket.isClosed) {
      try {
        val client = listen_socket.accept()
        log("accept")

        val server = listen_info.getServer(database)!!
        val server_e = endpointFactory.createFromServer(server)
        createConnection(SocketEndpoint(client), server_e)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  @Throws(Exception::class)
  fun createConnection(client: Endpoint, server: Endpoint) {
    val duplex =
      duplexFactory.createDuplexAsync(
        client,
        server,
        listen_info.getServer(database)!!.getEncoder()!!,
      )
    duplex.start()
    duplexManager.registerDuplex(duplex)
  }

  @Throws(Exception::class)
  override fun close() {
    listen_socket.close()
  }
}
