/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.http

import com.google.re2j.Pattern
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager
import packetproxy.CertCacheManager
import packetproxy.common.ClientKeyManager
import packetproxy.common.Utils
import packetproxy.model.CAs.CA
import packetproxy.model.ConfigString
import packetproxy.model.Configs
import packetproxy.model.Servers
import packetproxy.util.errWithStackTrace

class Https(
  private val configs: Configs,
  private val servers: Servers,
  private val certCacheManager: CertCacheManager,
  private val clientKeyManager: ClientKeyManager,
) {
  private val KS_PASS = "testtest".toCharArray()

  private val emptyKeyManagers: Array<KeyManager> =
    arrayOf(
      object : X509KeyManager {
        override fun getClientAliases(s: String, principals: Array<Principal>?): Array<String> =
          arrayOf()

        override fun chooseClientAlias(
          strings: Array<String>?,
          principals: Array<Principal>?,
          socket: Socket?,
        ): String? = null

        override fun getServerAliases(s: String, principals: Array<Principal>?): Array<String> =
          arrayOf()

        override fun chooseServerAlias(
          s: String?,
          principals: Array<Principal>?,
          socket: Socket?,
        ): String? = null

        override fun getCertificateChain(s: String): Array<X509Certificate> = arrayOf()

        override fun getPrivateKey(s: String): PrivateKey? = null
      }
    )

  @Throws(Exception::class)
  fun createSSLContext(commonName: String, ca: CA): SSLContext {
    var sslContext = SSLContext.getInstance("TLS")
    var domainNames =
      servers.queryResolvedByDNS().map { it.getIp()!! }.sortedWith(String::compareTo).toTypedArray()
    var ks: KeyStore = certCacheManager.getKeyStore(commonName, domainNames, ca)
    var kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    kmf.init(ks, KS_PASS)
    sslContext.init(kmf.keyManagers, null, null)
    return sslContext
  }

  @Throws(Exception::class)
  fun createServerSSLSocket(listen_port: Int, commonName: String, ca: CA): ServerSocket {
    var sslContext = createSSLContext(commonName, ca)
    var ssf = sslContext.serverSocketFactory
    return ssf.createServerSocket(listen_port) as SSLServerSocket
  }

  @Throws(Exception::class)
  fun createServerSSLSocket(
    listen_port: Int,
    commonName: String,
    ca: CA,
    ApplicationProtocol: String,
  ): ServerSocket {
    var serverSocket = createServerSSLSocket(listen_port, commonName, ca) as SSLServerSocket
    var sslp = serverSocket.sslParameters
    var serverAPs = arrayOf(ApplicationProtocol)
    sslp.applicationProtocols = serverAPs
    serverSocket.sslParameters = sslp
    return serverSocket
  }

  @Throws(Exception::class)
  private fun doHttpConnect(proxyAddr: InetSocketAddress, serverAddr: InetSocketAddress): Socket {
    var serverSocket = Socket(proxyAddr.address, proxyAddr.getPort())
    var proxyOut = serverSocket.getOutputStream()
    var proxyIn = serverSocket.getInputStream()
    proxyOut.write(
      String.format(
          "CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n",
          serverAddr.hostString,
          serverAddr.getPort(),
          serverAddr.hostString,
        )
        .toByteArray()
    )
    proxyOut.flush()
    var length: Int
    var input_data = ByteArray(1024)
    var total = 0
    while (proxyIn.read(input_data, total, input_data.size - total).also { length = it } != -1) {
      total += length
      if (Utils.indexOf(input_data, 0, total, "\r\n\r\n".toByteArray()) >= 0) {
        break
      }
      if (total >= input_data.size) {
        break
      }
    }
    var response = String(input_data, 0, total, Charsets.ISO_8859_1)
    var statusLine = response.lineSequence().firstOrNull().orEmpty()
    var statusMatch = Regex("""HTTP/\S+\s+(\d+)""").find(statusLine)
    var statusCode = statusMatch?.groupValues?.get(1)?.toIntOrNull() ?: 0
    if (statusCode !in 200..299) {
      serverSocket.close()
      throw Exception("Upstream CONNECT failed: $statusLine")
    }
    return serverSocket
  }

  @Throws(Exception::class)
  private fun applySni(sock: SSLSocket, serverName: String?) {
    if (serverName.isNullOrBlank()) return
    try {
      var params = sock.sslParameters
      params.serverNames = listOf(SNIHostName(serverName))
      sock.sslParameters = params
    } catch (_: IllegalArgumentException) {
      // Invalid SNI host name — skip
    }
  }

  @Throws(Exception::class)
  fun createBothSideSSLSockets(
    clientSocket: Socket,
    lookahead: InputStream?,
    serverAddr: InetSocketAddress,
    proxyAddr: InetSocketAddress?,
    serverName: String,
    ca: CA,
  ): Array<SSLSocket> {
    var clientSSLSocket =
      createSSLContext(serverName, ca).socketFactory.createSocket(clientSocket, lookahead, true)
        as SSLSocket
    clientSSLSocket.useClientMode = false

    var keyManagers =
      clientKeyManager.getKeyManagers(servers.queryByAddress(serverAddr)) ?: emptyKeyManagers
    var serverSSLSocket = arrayOfNulls<SSLSocket>(1)
    clientSSLSocket.setHandshakeApplicationProtocolSelector { _, clientProtocols ->
      try {
        var serverSocket: Socket =
          if (proxyAddr != null) {
            doHttpConnect(proxyAddr, serverAddr)
          } else {
            Socket(serverAddr.address, serverAddr.getPort())
          }
        serverSSLSocket[0] =
          createSSLSocketFactory(keyManagers).createSocket(serverSocket, null as InputStream?, true)
            as SSLSocket
        serverSSLSocket[0]!!.useClientMode = true
        var sp = serverSSLSocket[0]!!.sslParameters

        var alpns = clientProtocols.toMutableList()
        if (ConfigString(configs, "PriorityOrderOfHttpVersions").getString() == "HTTP1") {
          if (alpns.contains("http/1.1") || alpns.contains("http/1.0")) {
            alpns.remove("h2")
            alpns.remove("grpc")
            alpns.remove("grpc-exp")
          }
        }
        sp.applicationProtocols = alpns.toTypedArray()
        serverSSLSocket[0]!!.sslParameters = sp
        applySni(serverSSLSocket[0]!!, serverName)
        serverSSLSocket[0]!!.startHandshake()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
      serverSSLSocket[0]?.applicationProtocol
    }

    clientSSLSocket.startHandshake()

    /* case: ALPN is not supported */
    if (serverSSLSocket[0] == null) {
      var serverSocket: Socket =
        if (proxyAddr != null) {
          doHttpConnect(proxyAddr, serverAddr)
        } else {
          Socket(serverAddr.address, serverAddr.getPort())
        }
      serverSSLSocket[0] =
        createSSLSocketFactory(keyManagers).createSocket(serverSocket, null as InputStream?, true)
          as SSLSocket
      serverSSLSocket[0]!!.useClientMode = true
      applySni(serverSSLSocket[0]!!, serverName)
      serverSSLSocket[0]!!.startHandshake()
    }

    return arrayOf(clientSSLSocket, serverSSLSocket[0]!!)
  }

  @Throws(Exception::class)
  fun convertToServerSSLSocket(
    socket: Socket,
    commonName: String,
    ca: CA,
    `is`: InputStream,
  ): SSLSocket {
    var sslContext = createSSLContext(commonName, ca)
    var ssf = sslContext.socketFactory
    var ssl_socket = ssf.createSocket(socket, `is`, true) as SSLSocket
    ssl_socket.useClientMode = false

    var sslp = ssl_socket.sslParameters
    var serverAPs = arrayOf("http/1.1", "http/1.0")
    sslp.applicationProtocols = serverAPs
    ssl_socket.sslParameters = sslp

    ssl_socket.startHandshake()
    return ssl_socket
  }

  @Throws(Exception::class)
  fun createSSLSocketFactory(keyManagers: Array<KeyManager> = emptyKeyManagers): SSLSocketFactory {
    var sslContext = SSLContext.getInstance("TLS")
    var trustManagers =
      arrayOf(
        object : X509TrustManager {
          override fun checkClientTrusted(arg0: Array<X509Certificate>, arg1: String) {}

          override fun checkServerTrusted(arg0: Array<X509Certificate>, arg1: String) {}

          override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
      )
    sslContext.init(keyManagers, trustManagers, SecureRandom())
    return sslContext.socketFactory as SSLSocketFactory
  }

  @Throws(Exception::class)
  fun convertToClientSSLSocket(socket: Socket, alpn: String?): SSLSocket {
    var ssf = createSSLSocketFactory()
    var sock = ssf.createSocket(socket, null, socket.getPort(), false) as SSLSocket
    var sslp = sock.sslParameters
    var clientAPs =
      if (alpn != null && alpn.isNotEmpty()) {
        arrayOf(alpn)
      } else {
        arrayOf("h2", "http/1.1", "http/1.0")
      }
    sslp.applicationProtocols = clientAPs
    sock.sslParameters = sslp
    sock.startHandshake()
    return sock
  }

  @Throws(Exception::class)
  fun createClientSSLSocket(addr: InetSocketAddress, alpn: String?): SSLSocket {
    var ssf = createSSLSocketFactory()
    var sock = ssf.createSocket(addr.address, addr.getPort()) as SSLSocket
    var sslp = sock.sslParameters
    var clientAPs =
      if (alpn != null && alpn.isNotEmpty()) {
        arrayOf(alpn)
      } else {
        arrayOf("h2", "http/1.1", "http/1.0")
      }
    sslp.applicationProtocols = clientAPs
    sock.sslParameters = sslp
    sock.startHandshake()
    return sock
  }

  @Throws(Exception::class)
  fun createClientSSLSocket(
    addr: InetSocketAddress,
    SNIServerName: String?,
    alpn: String?,
  ): SSLSocket {
    var keyManagers =
      clientKeyManager.getKeyManagers(servers.queryByAddress(addr)) ?: emptyKeyManagers
    var ssf = createSSLSocketFactory(keyManagers)
    var sock = ssf.createSocket(addr.address, addr.getPort()) as SSLSocket
    var sslp = sock.sslParameters
    var clientAPs =
      if (alpn != null && alpn.isNotEmpty()) {
        arrayOf(alpn)
      } else {
        arrayOf("h2", "http/1.1", "http/1.0")
      }
    sslp.applicationProtocols = clientAPs
    sock.sslParameters = sslp
    applySni(sock, SNIServerName)
    sock.startHandshake()
    return sock
  }

  @Throws(Exception::class)
  fun getCommonName(addr: InetSocketAddress): String {
    var ssf = createSSLSocketFactory()
    var socket = ssf.createSocket(addr.address, addr.getPort()) as SSLSocket
    applySni(socket, addr.hostString)
    socket.startHandshake()
    var session = socket.session
    var servercerts = session.peerCertificates as Array<X509Certificate>

    var pattern = Pattern.compile("CN=([^,]+)", Pattern.CASE_INSENSITIVE)
    var matcher = pattern.matcher(servercerts[0].subjectDN.getName())
    if (matcher.find()) {
      return matcher.group(1)
    }
    return ""
  }
}
