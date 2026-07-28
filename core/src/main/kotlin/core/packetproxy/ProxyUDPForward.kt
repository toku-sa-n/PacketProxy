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

import java.net.InetSocketAddress
import packetproxy.common.UDPServerSocket
import packetproxy.common.UDPSocketEndpoint
import packetproxy.model.Database
import packetproxy.model.ListenPort
import packetproxy.model.Resolutions
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class ProxyUDPForward
@Throws(Exception::class)
constructor(
  private val listen_info: ListenPort,
  private val duplexFactory: DuplexFactory,
  private val duplexManager: DuplexManager,
  private val database: Database,
  private val resolutions: Resolutions,
) : Proxy() {
  private val listen_socket = UDPServerSocket(listen_info.getPort())

  override fun run() {
    try {
      while (true) {
        val client_endpoint = listen_socket.accept()
        log("accept")

        val serverAddr: InetSocketAddress =
          listen_info.getServer(database)!!.getAddress(resolutions)
        val server_endpoint = UDPSocketEndpoint(serverAddr)

        val duplex =
          duplexFactory.createDuplexAsync(
            client_endpoint,
            server_endpoint,
            listen_info.getServer(database)!!.getEncoder()!!,
          )
        duplex.start()
        duplexManager.registerDuplex(duplex)
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  override fun close() {
    listen_socket.close()
  }
}
