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

import packetproxy.model.Database
import packetproxy.model.ListenPort
import packetproxy.model.Resolutions
import packetproxy.quic.service.connection.ClientConnections
import packetproxy.quic.service.connection.ServerConnection
import packetproxy.quic.value.ConnectionIdPair
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class ProxyQuicForward
@Throws(Exception::class)
constructor(
  private val listen_info: ListenPort,
  private val duplexFactory: DuplexFactory,
  private val duplexManager: DuplexManager,
  certCacheManager: CertCacheManager,
  private val resolutions: Resolutions,
  private val database: Database,
) : Proxy() {
  private val clientConnections =
    ClientConnections(listen_info.getPort(), listen_info.getCA().get(), certCacheManager)

  override fun run() {
    try {
      while (true) {
        val clientConnection = clientConnections.accept()
        log("accept")

        val server = listen_info.getServer(database)!!
        val serverName = server.getIp()!!
        log("[QUIC-forward!] %s", serverName)

        val serverConnection =
          ServerConnection(
            ConnectionIdPair.generateRandom(),
            serverName,
            server.getPort(),
            resolutions,
          )

        val duplex =
          duplexFactory.createDuplexAsync(
            clientConnection,
            serverConnection,
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
    clientConnections.close()
  }
}
