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

import com.google.re2j.Pattern
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import packetproxy.common.Endpoint
import packetproxy.common.EndpointFactory
import packetproxy.common.StringUtils
import packetproxy.http.Http
import packetproxy.model.Database
import packetproxy.model.ListenPort
import packetproxy.model.Resolutions
import packetproxy.model.Server
import packetproxy.model.Servers
import packetproxy.util.err
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class ProxyHttpTransparent
@Throws(Exception::class)
constructor(
  private val listen_socket: ServerSocket,
  private val listen_info: ListenPort,
  private val duplexFactory: DuplexFactory,
  private val duplexManager: DuplexManager,
  private val endpointFactory: EndpointFactory,
  private val servers: Servers,
  private val resolutions: Resolutions,
  private val database: Database,
) : Proxy() {
  @Throws(Exception::class)
  override fun close() {
    listen_socket.close()
  }

  override fun run() {
    while (!listen_socket.isClosed) {
      try {
        val client = listen_socket.accept()
        log("[ProxyHttpTransparent]: accept")
        createHttpTransparentProxy(client)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  data class HostPort(val hostName: String, val port: Int) {
    @Throws(Exception::class)
    fun getInetSocketAddress(resolutions: Resolutions): InetSocketAddress =
      InetSocketAddress(PrivateDNSClient().getByName(hostName, resolutions), port)
  }

  @Throws(Exception::class)
  private fun parseHostName(buffer: ByteArray): HostPort {
    var start = 0
    if (StringUtils.binaryFind(buffer, "Host:".toByteArray()).also { start = it } > 0) {
      start += 5
    } else if (StringUtils.binaryFind(buffer, "host:".toByteArray()).also { start = it } > 0) {
      start += 5
    } else {
      throw Exception("Host: header field is not found in beginning of 4096 bytes of packets.")
    }
    val end = StringUtils.binaryFind(buffer, "\n".toByteArray(), start)
    val serverCand = String(buffer, start, end - start)
    var server = ""
    var port = 80
    val pattern = Pattern.compile("^ *([^:\\n\\r]+)(?::([0-9]+))?")
    val matcher = pattern.matcher(serverCand)
    if (matcher.find()) {
      if (matcher.group(1) != null) server = matcher.group(1)
      if (matcher.group(2) != null) port = matcher.group(2).toInt()
    } else {
      throw Exception("Host: header field format is not recognized.")
    }
    return HostPort(server, port)
  }

  @Throws(Exception::class)
  private fun createHttpTransparentProxy(client: Socket) {
    val ins = client.inputStream
    val bout = ByteArrayOutputStream()
    var hostPort: HostPort? = null

    val input_data = ByteArray(4096)
    var length: Int
    while (ins.read(input_data, 0, input_data.size).also { length = it } != -1) {
      bout.write(input_data, 0, length)
      var accepted_input_size = 0
      val currentBuffer = bout.toByteArray()
      if (
        currentBuffer.isNotEmpty() &&
          Http.parseHttpDelimiter(currentBuffer).also { accepted_input_size = it } > 0
      ) {
        hostPort = parseHostName(currentBuffer.copyOfRange(0, accepted_input_size))
        break
      }
    }
    if (hostPort == null) {
      err(String(input_data))
      err("bout length == %d", bout.size())
      if (bout.size() == 0) {
        err("empty request!!")
        return
      }
      err("HTTP Host field is not found.")
      return
    }

    val lookaheadBuffer = ByteArrayInputStream(bout.toByteArray())

    try {
      val client_e = endpointFactory.createClientEndpoint(client, lookaheadBuffer)

      val server_e: Endpoint =
        if (listen_info.getServer(database) != null) { // upstream proxy
          endpointFactory.createServerEndpoint(
            listen_info.getServer(database)!!.getAddress(resolutions)
          )
        } else {
          endpointFactory.createServerEndpoint(hostPort.getInetSocketAddress(resolutions))
        }

      val server = servers.queryByHostNameAndPort(hostPort.hostName, hostPort.port)
      createConnection(client_e, server_e, server)
    } catch (e: ConnectException) {
      val addr = hostPort.getInetSocketAddress(resolutions)
      log("Connection Refused: %s:%d", addr.hostName, addr.getPort())
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  fun createConnection(client_e: Endpoint, server_e: Endpoint, server: Server?) {
    val duplex =
      if (server == null) duplexFactory.createDuplexAsync(client_e, server_e, "HTTP")
      else duplexFactory.createDuplexAsync(client_e, server_e, server.getEncoder()!!)
    duplex.start()
    duplexManager.registerDuplex(duplex)
  }
}
