/*
 * Copyright 2022 DeNA Co., Ltd.
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

import packetproxy.model.ListenPort
import packetproxy.model.Servers
import packetproxy.quic.service.connection.ClientConnections
import packetproxy.quic.service.connection.ServerConnection
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.Logging.log

class ProxyQuicTransparent
@Throws(Exception::class)
constructor(private val listen_info: ListenPort) : Proxy() {
  private val clientConnections =
    ClientConnections(listen_info.getPort(), listen_info.getCA().get())

  override fun run() {
    try {
      while (true) {
        val clientConnection = clientConnections.accept()
        log("accept")

        val sniServerName = clientConnection.getSNI()
        log("[QUIC-forward! using SNI] %s", sniServerName)

        val serverConnection =
          ServerConnection(ConnectionIdPair.generateRandom(), sniServerName, listen_info.getPort())

        var encoder = "HTTP"
        val server = Servers.getInstance().queryByHostName(sniServerName)
        if (server != null) {
          val encoderTemp = server.getEncoder()
          if (encoderTemp != null) {
            encoder = encoderTemp
          }
        }

        val alpn = if (encoder == "HTTP") "h3" else null

        val duplex =
          DuplexFactory.createDuplexAsync(clientConnection, serverConnection, encoder, alpn)

        duplex.start()
        DuplexManager.getInstance().registerDuplex(duplex)
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  override fun close() {
    clientConnections.close()
  }
}
