/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.http

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import javax.net.ssl.SSLSocket
import packetproxy.common.SSLSocketEndpoint
import packetproxy.common.Utils

class HttpsProxySocketEndpoint(proxySocket: SSLSocket, serverAddr: InetSocketAddress) :
  SSLSocketEndpoint(proxySocket, "proxy") {
  private var proxyIn: InputStream
  private var proxyOut: OutputStream
  private val requestTemplate = "CONNECT %s:%d HTTP/1.0\r\nHost: %s\r\n\r\n"

  init {
    proxyOut = socket.getOutputStream()
    proxyOut.write(
      requestTemplate
        .format(serverAddr.hostString, serverAddr.getPort(), serverAddr.hostString)
        .toByteArray()
    )
    proxyOut.flush()
    proxyIn = socket.getInputStream()
    val inputData = ByteArray(1024)
    var length: Int
    while (proxyIn.read(inputData, 0, inputData.size).also { length = it } != -1) {
      if (Utils.indexOf(inputData, 0, length, "\r\n\r\n".toByteArray()) >= 0) break
    }
  }

  override fun getAddress(): InetSocketAddress =
    InetSocketAddress(socket.inetAddress, socket.getPort())

  @Throws(Exception::class) override fun getInputStream(): InputStream = socket.getInputStream()

  @Throws(Exception::class) override fun getOutputStream(): OutputStream = socket.getOutputStream()

  override fun getName(): String? = null

  override fun getApplicationProtocol(): String = socket.getApplicationProtocol()
}
