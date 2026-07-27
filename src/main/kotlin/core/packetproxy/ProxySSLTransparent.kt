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

import com.google.re2j.Pattern
import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import javax.net.ssl.SNIServerName
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.EndpointFactory
import packetproxy.common.I18nString
import packetproxy.common.SSLCapabilities
import packetproxy.common.SSLExplorer
import packetproxy.common.SSLSocketEndpoint
import packetproxy.common.SocketEndpoint
import packetproxy.common.WrapEndpoint
import packetproxy.encode.EncodeHTTPBase
import packetproxy.model.ListenPort
import packetproxy.model.SSLPassThroughs
import packetproxy.model.Server
import packetproxy.model.Servers
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.Logging.log

class ProxySSLTransparent
@Throws(Exception::class)
constructor(private val listen_socket: ServerSocket, private val listen_info: ListenPort) :
  Proxy() {
  @Throws(Exception::class)
  override fun close() {
    listen_socket.close()
  }

  override fun run() {
    val clients = ArrayList<Socket>()
    while (!listen_socket.isClosed) {
      try {
        val client = listen_socket.accept()
        clients.add(client)
        log("[ProxySSLTransparent]: accept")
        checkTransparentSSLProxy(client, listen_socket.localPort)
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
  private fun checkTransparentSSLProxy(client: Socket, proxyPort: Int) {
    val ins = client.getInputStream()

    var buffer = ByteArray(0xFF)
    var position = 0
    val capabilities: SSLCapabilities?

    // Read the header of TLS record
    while (position < SSLExplorer.RECORD_HEADER_SIZE) {
      val count = SSLExplorer.RECORD_HEADER_SIZE - position
      val n = ins.read(buffer, position, count)
      if (n < 0) {
        throw Exception("unexpected end of stream!")
      }
      position += n
    }

    // Get the required size to explore the SSL capabilities
    val recordLength = SSLExplorer.getRequiredSize(buffer, 0, position)
    if (buffer.size < recordLength) {
      buffer = buffer.copyOf(recordLength)
    }

    while (position < recordLength) {
      val count = recordLength - position
      val n = ins.read(buffer, position, count)
      if (n < 0) {
        throw Exception("unexpected end of stream!")
      }
      position += n
    }

    // Explore
    capabilities = SSLExplorer.explore(buffer, 0, recordLength)
    if (capabilities == null) {
      throw Exception("capabilities not found.")
    }

    val serverNames: List<SNIServerName> = capabilities.getServerNames()
    if (serverNames.isEmpty()) {
      /* SNIヘッダが見当たらないので、通信をHTTP1を強制し、Hostヘッダを覗くことで宛先を知る必要がある */
      /* クライアントわたすサーバ証明書は、宛先がわからないので packetproxy.com とする */
      val bais = ByteArrayInputStream(buffer, 0, position)
      val client_e =
        EndpointFactory.createClientEndpointFromSNIServerName(
          client,
          "packetproxy.com",
          listen_info.getCA().get(),
          bais,
        )

      /* 少しだけ先読みし、Hostフィールドから次に接続するべきサーバー名を入手 */
      val `in` = client_e.getInputStream()
      val buff = ByteArray(4096)
      val length = `in`.read(buff)
      val str = String(buff)
      val pattern = Pattern.compile("Host: *([^\\r\\n]+)", Pattern.CASE_INSENSITIVE)
      val matcher = pattern.matcher(str)
      val serverName: String
      if (matcher.find()) {
        serverName = matcher.group(1)
        log("[SSL-forward!] %s", serverName)
      } else {
        throw Exception(I18nString.get("[Error] SNI header was not found in SSL packets."))
      }
      val wep_e = WrapEndpoint(client_e, ArrayUtils.subarray(buff, 0, length))
      val serverAddr = InetSocketAddress(PrivateDNSClient.getByName(serverName), proxyPort)
      // SNIヘッダが無い場合、SSLPassThroughは使えない
      val server = Servers.getInstance().queryByHostNameAndPort(serverName, proxyPort)
      val server_e = SSLSocketEndpoint(serverAddr, serverName, null)
      createConnection(wep_e, server_e, server)
    } else {
      for (serverE in serverNames) {
        val serverName = String(serverE.encoded) // 接続先サーバを取得
        if (listen_info.getServer() != null) { // upstream proxy
          log("[SSL-forward through upstream proxy! using SNI] %s", serverName)
        } else {
          log("[SSL-forward! using SNI] %s", serverName)
        }
        val bais = ByteArrayInputStream(buffer, 0, position)

        /* check server connection */
        var serverAddr: InetSocketAddress
        try {
          serverAddr =
            if (listen_info.getServer() != null) { // upstream proxy
              listen_info.getServer()!!.getAddress()
            } else {
              InetSocketAddress(PrivateDNSClient.getByName(serverName), proxyPort)
            }
          val s = Socket()
          s.connect(serverAddr, 500) /* timeout: 500ms */
          s.close()
        } catch (e: Exception) {
          /* listenポート番号と同じポート番号へアクセスできないので443番にフォールバックする */
          serverAddr = InetSocketAddress(PrivateDNSClient.getByName(serverName), 443)
          log("[Fallback port] %d -> 443", proxyPort)
        }

        if (SSLPassThroughs.getInstance().includes(serverName, listen_info.getPort())) {
          val server_e = SocketEndpoint(serverAddr)
          val client_e = SocketEndpoint(client, bais)
          val duplex = DuplexAsync(client_e, server_e)
          duplex.start()
        } else {
          val server =
            Servers.getInstance().queryByHostNameAndPort(serverName, serverAddr.getPort())
          val eps =
            EndpointFactory.createBothSideSSLEndpoints(
              client,
              bais,
              serverAddr,
              null,
              serverName,
              listen_info.getCA().get(),
            )
          createConnection(eps[0], eps[1], server)
        }
      }
    }
  }

  @Throws(Exception::class)
  fun createConnection(client_e: SSLSocketEndpoint, server_e: SSLSocketEndpoint, server: Server?) {
    var duplex: DuplexAsync
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
}
