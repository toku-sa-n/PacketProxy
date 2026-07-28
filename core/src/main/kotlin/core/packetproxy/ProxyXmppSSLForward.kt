/*
 * Copyright 2019,2022 DeNA Co., Ltd.
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

import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import javax.net.ssl.SSLSocket
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.Endpoint
import packetproxy.common.SocketEndpoint
import packetproxy.http.Https
import packetproxy.model.Database
import packetproxy.model.ListenPort
import packetproxy.model.Resolutions
import packetproxy.util.err
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class ProxyXmppSSLForward(
  private val listen_socket: ServerSocket,
  private val listen_info: ListenPort,
  private val duplexFactory: DuplexFactory,
  private val duplexManager: DuplexManager,
  private val https: Https,
  private val database: Database,
  private val resolutions: Resolutions,
) : Proxy() {
  private var finishFlag = false

  override fun run() {
    while (!listen_socket.isClosed) {
      try {
        val client = listen_socket.accept()
        log("accept")

        val server = Socket()
        server.connect(listen_info.getServer(database)!!.getAddress(resolutions))

        skipDataUntilSSLConnectionStarted(client, server)

        val clientSSLSocket =
          https
            .createSSLContext(
              listen_info.getServer(database)!!.getIp()!!,
              listen_info.getCA().get(),
            )
            .socketFactory
            .createSocket(client, null as InputStream?, true) as SSLSocket
        val serverSSLSocket =
          https.createSSLSocketFactory().createSocket(server, null as InputStream?, true)
            as SSLSocket
        clientSSLSocket.useClientMode = false
        serverSSLSocket.useClientMode = true
        createConnection(SocketEndpoint(clientSSLSocket), SocketEndpoint(serverSSLSocket))
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  @Throws(Exception::class)
  private fun skipDataUntilSSLConnectionStarted(client: Socket, server: Socket) {
    val cI: InputStream = client.inputStream
    val cO: OutputStream = client.outputStream
    val sI: InputStream = server.inputStream
    val sO: OutputStream = server.outputStream

    val clientT = Thread {
      try {
        val buff = ByteArray(4096)
        do {
          if (finishFlag) return@Thread
          if (cI.available() > 0) {
            val len = cI.read(buff, 0, buff.size)
            if (len < 0) {
              err("ERROR: xmpp client socket closed")
              return@Thread
            }
            sO.write(buff, 0, len)
          }
          sleep(1000) // wait 1s
        } while (true)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    val serverT = Thread {
      try {
        val buff = ByteArray(4096)
        do {
          if (finishFlag) return@Thread
          if (sI.available() > 0) {
            val len2 = sI.read(buff, 0, buff.size)
            if (len2 < 0) {
              err("ERROR: xmpp server socket closed")
              return@Thread
            }
            val body = String(ArrayUtils.subarray(buff, 0, len2))
            if (body.contains("proceed")) {
              finishFlag = true
              while (clientT.isAlive) {
                sleep(1000)
              }
            }
            cO.write(buff, 0, len2)
          }
        } while (true)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    clientT.start()
    serverT.start()
    clientT.join()
    serverT.join()
    finishFlag = false
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
