/*
 * Copyright 2025 DeNA Co., Ltd.
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
import packetproxy.common.*
import packetproxy.http.Https
import packetproxy.model.ListenPort
import packetproxy.util.Logging

class ProxyFactory(
  private val duplexFactory: DuplexFactory,
  private val duplexManager: DuplexManager,
  private val endpointFactory: packetproxy.common.EndpointFactory,
  private val encoderManager: EncoderManager,
  private val modelServices: packetproxy.model.ModelServices,
  private val https: Https,
) {
  @Throws(Exception::class)
  fun create(listenInfo: ListenPort): Proxy {
    val type = listenInfo.getType()
    val port = listenInfo.getPort()

    Logging.log("type is $type")
    Logging.log(i18nString("Start listening port %d.", port))

    return when (type) {
      ListenPort.TYPE.UDP_FORWARDER ->
        ProxyUDPForward(
          listenInfo,
          duplexFactory,
          duplexManager,
          modelServices.database,
          modelServices.resolutions,
        )
      ListenPort.TYPE.QUIC_FORWARDER ->
        ProxyQuicForward(
          listenInfo,
          duplexFactory,
          duplexManager,
          modelServices.certCacheManager,
          modelServices.resolutions,
          modelServices.database,
        )
      ListenPort.TYPE.QUIC_TRANSPARENT_PROXY ->
        ProxyQuicTransparent(
          listenInfo,
          duplexFactory,
          duplexManager,
          modelServices.servers,
          modelServices.certCacheManager,
          modelServices.resolutions,
        )

      else -> {
        val listenSocket = ServerSocket(port)

        when (type) {
          ListenPort.TYPE.HTTP_PROXY ->
            ProxyHttp(
              listenSocket,
              listenInfo,
              duplexFactory,
              endpointFactory,
              modelServices,
              https,
            )
          ListenPort.TYPE.SSL_FORWARDER ->
            ProxySSLForward(
              listenSocket,
              listenInfo,
              duplexFactory,
              duplexManager,
              endpointFactory,
              encoderManager,
              modelServices.sslPassThroughs,
              modelServices.database,
              modelServices.resolutions,
            )
          ListenPort.TYPE.HTTP_TRANSPARENT_PROXY ->
            ProxyHttpTransparent(
              listenSocket,
              listenInfo,
              duplexFactory,
              endpointFactory,
              modelServices.servers,
              modelServices.resolutions,
              modelServices.database,
            )
          ListenPort.TYPE.SSL_TRANSPARENT_PROXY ->
            ProxySSLTransparent(
              listenSocket,
              listenInfo,
              duplexFactory,
              duplexManager,
              endpointFactory,
              encoderManager,
              modelServices.servers,
              modelServices.sslPassThroughs,
              modelServices.resolutions,
              modelServices.database,
            )

          else -> {
            listenSocket.setReuseAddress(true)

            when (type) {
              ListenPort.TYPE.XMPP_SSL_FORWARDER ->
                ProxyXmppSSLForward(
                  listenSocket,
                  listenInfo,
                  duplexFactory,
                  duplexManager,
                  https,
                  modelServices.database,
                  modelServices.resolutions,
                )
              else ->
                ProxyForward(
                  listenSocket,
                  listenInfo,
                  duplexFactory,
                  duplexManager,
                  endpointFactory,
                  modelServices.database,
                )
            }
          }
        }
      }
    }
  }
}
