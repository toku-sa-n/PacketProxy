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

import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import packetproxy.common.CryptUtils
import packetproxy.common.Endpoint
import packetproxy.common.EndpointFactory
import packetproxy.common.SSLSocketEndpoint
import packetproxy.common.UniqueID
import packetproxy.controller.InterceptController
import packetproxy.http.Http
import packetproxy.http.HttpsProxySocketEndpoint
import packetproxy.model.Modifications
import packetproxy.model.OneShotPacket
import packetproxy.model.Packet
import packetproxy.model.Packets
import packetproxy.model.Servers

object DuplexFactory {
  // 1MB以上のパケットは最後のタイミングだけHistoryに記録する、それ未満はパケットが更新されるたびにHistoryを更新する
  private const val SKIP_LENGTH = 1 * 1024 * 1024
  // 10MB以上のパケットはHistoryには記録しない
  private const val TOO_LARGE_LENGTH = 10 * 1024 * 1024

  @JvmStatic
  @Throws(Exception::class)
  fun createDuplexSync(
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    encoder_name: String,
    ALPN: String?,
  ): DuplexSync {
    val duplex = DuplexSync(server_endpoint)
    prepareDuplex(duplex, client_endpoint, server_endpoint, encoder_name, ALPN)
    return duplex
  }

  @JvmStatic
  @Throws(Exception::class)
  fun createDuplexAsync(
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    encoder_name: String,
  ): DuplexAsync {
    val duplex = DuplexAsync(client_endpoint, server_endpoint)
    prepareDuplex(duplex, client_endpoint, server_endpoint, encoder_name, null)
    return duplex
  }

  @JvmStatic
  @Throws(Exception::class)
  fun createDuplexAsync(
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    encoder_name: String,
    ALPN: String?,
  ): DuplexAsync {
    val duplex = DuplexAsync(client_endpoint, server_endpoint)
    prepareDuplex(duplex, client_endpoint, server_endpoint, encoder_name, ALPN)
    return duplex
  }

  @Throws(Exception::class)
  private fun prepareDuplex(
    duplex: Duplex,
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    encoder_name: String,
    ALPN: String?,
  ) {
    val client_addr = client_endpoint.getAddress()
    val server_addr = server_endpoint.getAddress()
    val use_ssl =
      server_endpoint is SSLSocketEndpoint || server_endpoint is HttpsProxySocketEndpoint

    duplex.addDuplexEventListener(
      object : Duplex.DuplexEventListener {
        private val packets = Packets.getInstance()
        private val encoder = EncoderManager.getInstance().createInstance(encoder_name, ALPN)
        private val mods = Modifications.getInstance()
        private var client_packet: Packet? = null
        private var server_packet: Packet? = null

        @Throws(Exception::class)
        override fun onClientPacketReceived(data: ByteArray): Int =
          encoder.checkRequestDelimiter(data)

        @Throws(Exception::class)
        override fun onServerPacketReceived(data: ByteArray): Int =
          encoder.checkResponseDelimiter(data)

        @Throws(Exception::class)
        override fun onClientChunkReceived(data: ByteArray): ByteArray {
          val initialGroupId = UniqueID.getInstance().createId()
          client_packet =
            Packet(
              0,
              client_addr,
              server_addr,
              server_endpoint.getName() ?: "",
              use_ssl,
              encoder_name,
              ALPN ?: "",
              Packet.Direction.CLIENT,
              duplex.hashCode(),
              initialGroupId,
            )
          client_packet!!.setReceivedData(data)
          var decoded_data = encoder.decodeClientRequest(client_packet!!)
          client_packet!!.setDecodedData(decoded_data)
          // groupIdはencoder.setGroupId()で変更される可能性があるため、
          // GUIHistoryへの通知（packets.update）はgroupId確定後に行う
          encoder.setGroupId(client_packet!!) /* 実行するのはsetDecodedDataのあと */
          if (data.size < SKIP_LENGTH) {
            packets.update(client_packet!!)
          }

          val server = Servers.getInstance().queryByAddress(server_addr)
          decoded_data = mods.replaceOnRequest(decoded_data, server, client_packet!!)

          val decoded_hash = CryptUtils.sha1(decoded_data)

          val intercepted_data = runBlocking {
            InterceptController.getInstance().received(decoded_data, server, client_packet!!).fold({
              ByteArray(0)
            }) {
              it
            }
          }

          val intercepted_hash = CryptUtils.sha1(intercepted_data)
          client_packet!!.setModifiedData(intercepted_data)
          if (intercepted_data.isNotEmpty() && !Arrays.equals(decoded_hash, intercepted_hash)) {
            client_packet!!.setModified()
          }
          if (data.size < SKIP_LENGTH) {
            packets.update(client_packet!!)
          }
          if (intercepted_data.isEmpty()) {
            /* drop */
            client_packet!!.setModified()
            packets.update(client_packet!!)
            return ByteArray(0)
          }
          return intercepted_data
        }

        @Throws(Exception::class)
        override fun onServerChunkReceived(data: ByteArray): ByteArray {
          val group_id =
            if (client_packet != null) {
              client_packet!!.getGroup()
            } else {
              // サーバから先にレスポンスがあった場合
              UniqueID.getInstance().createId()
            }
          server_packet =
            Packet(
              0,
              client_addr,
              server_addr,
              server_endpoint.getName() ?: "",
              use_ssl,
              encoder_name,
              ALPN ?: "",
              Packet.Direction.SERVER,
              duplex.hashCode(),
              group_id,
            )
          packets.update(server_packet!!)
          server_packet!!.setReceivedData(data)
          if (data.size < SKIP_LENGTH) {
            packets.update(server_packet!!)
          }
          var decoded_data = encoder.decodeServerResponse(client_packet, server_packet!!)
          server_packet!!.setDecodedData(decoded_data)
          encoder.setGroupId(server_packet!!) /* 実行するのはsetDecodedDataのあと */
          server_packet!!.setContentType(encoder.getContentType(client_packet, server_packet!!))
          if (data.size < SKIP_LENGTH) {
            packets.update(server_packet!!)
          }
          if (server_packet!!.getContentType() != "") {
            client_packet!!.setContentType(server_packet!!.getContentType() ?: "")
            packets.update(client_packet!!)
          }

          val server = Servers.getInstance().queryByAddress(server_addr)
          decoded_data = mods.replaceOnResponse(decoded_data, server, server_packet!!)

          val decoded_hash = CryptUtils.sha1(decoded_data)

          val intercepted_data = runBlocking {
            InterceptController.getInstance()
              .received(decoded_data, server, client_packet!!, server_packet!!)
              .fold({ ByteArray(0) }) { it }
          }

          val intercepted_hash = CryptUtils.sha1(intercepted_data)
          server_packet!!.setModifiedData(intercepted_data)
          if (intercepted_data.isNotEmpty() && !Arrays.equals(decoded_hash, intercepted_hash)) {
            server_packet!!.setModified()
          }
          if (data.size < SKIP_LENGTH) {
            packets.update(server_packet!!)
          }
          if (intercepted_data.isEmpty()) {
            /* drop */
            server_packet!!.setModified()
            packets.update(server_packet!!)
            return ByteArray(0)
          }
          return intercepted_data
        }

        @Throws(Exception::class)
        override fun onClientChunkSend(data: ByteArray): ByteArray {
          val encoded_data = encoder.encodeClientRequest(client_packet!!)
          client_packet!!.setSentData(encoded_data)
          packets.update(client_packet!!)
          return encoded_data
        }

        @Throws(Exception::class)
        override fun onServerChunkSend(data: ByteArray): ByteArray {
          val encoded_data = encoder.encodeServerResponse(client_packet, server_packet!!)

          // 画像データの場合には、ディスクスペース節約のためにDBに保存しない
          if ((server_packet!!.getContentType() ?: "").startsWith("image")) {
            val http = Http.create(server_packet!!.getDecodedData())
            http.body =
              "[Info] body data were deleted by PacketProxy to save space of disc.".toByteArray()
            server_packet!!.setReceivedData(http.toByteArray())
            server_packet!!.setDecodedData(http.toByteArray())
            server_packet!!.setModifiedData(http.toByteArray())
            server_packet!!.setSentData(http.toByteArray())
          } else {
            server_packet!!.setSentData(encoded_data)
          }

          packets.update(server_packet!!)
          return encoded_data
        }

        @Throws(Exception::class)
        override fun onClientChunkSendForced(data: ByteArray): ByteArray {
          val client_packet =
            Packet(
              0,
              client_addr,
              server_addr,
              server_endpoint.getName() ?: "",
              use_ssl,
              encoder_name,
              ALPN ?: "",
              Packet.Direction.CLIENT,
              duplex.hashCode(),
              UniqueID.getInstance().createId(),
            )
          packets.update(client_packet!!)
          client_packet.setModified()
          client_packet.setDecodedData(data)
          if (data.size < SKIP_LENGTH) {
            packets.update(client_packet!!)
          }
          client_packet.setModifiedData(data)
          client_packet.setModifiedData(encoder.procBeforeResendClientRequest(client_packet))
          if (data.size < SKIP_LENGTH) {
            packets.update(client_packet!!)
          }
          val encoded_data = encoder.encodeClientRequest(client_packet!!)
          client_packet.setSentData(encoded_data)
          packets.update(client_packet!!)
          return encoded_data
        }

        @Throws(Exception::class)
        override fun onServerChunkSendForced(data: ByteArray): ByteArray {
          val group_id =
            if (client_packet != null) {
              client_packet!!.getGroup()
            } else {
              // サーバから先にレスポンスがあった場合
              UniqueID.getInstance().createId()
            }
          val server_packet =
            Packet(
              0,
              client_addr,
              server_addr,
              server_endpoint.getName() ?: "",
              use_ssl,
              encoder_name,
              ALPN ?: "",
              Packet.Direction.SERVER,
              duplex.hashCode(),
              group_id,
            )
          packets.update(server_packet!!)
          server_packet.setDecodedData(data)
          if (data.size < SKIP_LENGTH) {
            packets.update(server_packet!!)
          }
          server_packet.setModifiedData(data)
          server_packet.setModifiedData(encoder.procBeforeResendServerResponse(server_packet))
          if (data.size < SKIP_LENGTH) {
            packets.update(server_packet!!)
          }
          val encoded_data = encoder.encodeServerResponse(client_packet, server_packet!!)
          server_packet.setSentData(encoded_data)
          packets.update(server_packet!!)
          return encoded_data
        }

        @Throws(Exception::class)
        override fun onClientChunkArrived(data: ByteArray) {
          encoder.clientRequestArrived(data)
        }

        @Throws(Exception::class)
        override fun onServerChunkArrived(data: ByteArray) {
          encoder.serverResponseArrived(data)
        }

        @Throws(Exception::class)
        override fun onClientChunkPassThrough(): ByteArray? = encoder.passThroughClientRequest()

        @Throws(Exception::class)
        override fun onServerChunkPassThrough(): ByteArray? = encoder.passThroughServerResponse()

        @Throws(Exception::class)
        override fun onClientChunkAvailable(): ByteArray? = encoder.clientRequestAvailable()

        @Throws(Exception::class)
        override fun onServerChunkAvailable(): ByteArray? = encoder.serverResponseAvailable()

        @Throws(Exception::class)
        override fun onClientChunkFlowControl(data: ByteArray) {
          encoder.putToClientFlowControlledQueue(data)
        }

        @Throws(Exception::class)
        override fun onServerChunkFlowControl(data: ByteArray) {
          encoder.putToServerFlowControlledQueue(data)
        }

        @Throws(Exception::class)
        override fun closeClientChunkFlowControl() {
          encoder.closeClientFlowControlledQueue()
        }

        @Throws(Exception::class)
        override fun closeServerChunkFlowControl() {
          encoder.closeServerFlowControlledQueue()
        }

        @Throws(Exception::class)
        override fun getClientChunkFlowControlSink(): InputStream =
          encoder.getClientFlowControlledInputStream()

        @Throws(Exception::class)
        override fun getServerChunkFlowControlSink(): InputStream =
          encoder.getServerFlowControlledInputStream()
      }
    )
  }

  @JvmStatic
  @Throws(Exception::class)
  fun createDuplexSyncFromOneShotPacket(oneshot: OneShotPacket): DuplexSync {
    val duplex = DuplexSync(EndpointFactory.createFromOneShotPacket(oneshot))
    duplex.addDuplexEventListener(
      object : Duplex.DuplexEventListener {
        private val packets = Packets.getInstance()
        private val encoder =
          EncoderManager.getInstance().createInstance(oneshot.getEncoder() ?: "", oneshot.getAlpn())
        private var client_packet: Packet? = null
        private var server_packet: Packet? = null

        @Throws(Exception::class)
        override fun onClientPacketReceived(data: ByteArray): Int = data.size

        @Throws(Exception::class)
        override fun onServerPacketReceived(data: ByteArray): Int =
          encoder.checkResponseDelimiter(data)

        @Throws(Exception::class)
        override fun onClientChunkReceived(data: ByteArray): ByteArray {
          /* do nothing so far */
          return data
        }

        @Throws(Exception::class)
        override fun onServerChunkReceived(data: ByteArray): ByteArray {
          val group_id =
            if (client_packet != null) {
              client_packet!!.getGroup()
            } else {
              // サーバから先にレスポンスがあった場合
              UniqueID.getInstance().createId()
            }
          server_packet =
            Packet(
              0,
              oneshot.getClient(),
              oneshot.getServer(),
              oneshot.getServerName() ?: "",
              oneshot.getUseSSL(),
              oneshot.getEncoder() ?: "",
              oneshot.getAlpn() ?: "",
              Packet.Direction.SERVER,
              duplex.hashCode(),
              group_id,
            )
          // OneShotPacketからjob_idとtemporary_idを引き継ぎ
          server_packet!!.setJobId(oneshot.getJobId())
          server_packet!!.setTemporaryId(oneshot.getTemporaryId())
          packets.update(server_packet!!)
          server_packet!!.setReceivedData(data)
          if (data.size < SKIP_LENGTH) {
            packets.update(server_packet!!)
          }
          val decoded_data = encoder.decodeServerResponse(client_packet, server_packet!!)
          server_packet!!.setDecodedData(decoded_data)
          server_packet!!.setContentType(encoder.getContentType(client_packet, server_packet!!))
          if (server_packet!!.getContentType() != "") {
            client_packet!!.setContentType(server_packet!!.getContentType() ?: "")
            packets.update(client_packet!!)
          }
          server_packet!!.setModifiedData(decoded_data)
          packets.update(server_packet!!)
          if (decoded_data.isEmpty()) {
            /* drop */
            server_packet!!.setModified()
            packets.update(server_packet!!)
            return ByteArray(0)
          }
          return decoded_data
        }

        @Throws(Exception::class)
        override fun onClientChunkSend(data: ByteArray): ByteArray {
          client_packet =
            Packet(
              0,
              oneshot.getClient(),
              oneshot.getServer(),
              oneshot.getServerName() ?: "",
              oneshot.getUseSSL(),
              oneshot.getEncoder() ?: "",
              oneshot.getAlpn() ?: "",
              Packet.Direction.CLIENT,
              duplex.hashCode(),
              UniqueID.getInstance().createId(),
            )
          // OneShotPacketからjob_idとtemporary_idを引き継ぎ
          client_packet!!.setJobId(oneshot.getJobId())
          client_packet!!.setTemporaryId(oneshot.getTemporaryId())
          client_packet!!.setModified()
          client_packet!!.setReceivedData(data)
          client_packet!!.setDecodedData(data)
          client_packet!!.setModifiedData(data)
          if (data.size < SKIP_LENGTH) {
            packets.update(client_packet!!)
          }
          val encoded_data = encoder.encodeClientRequest(client_packet!!)
          client_packet!!.setSentData(encoded_data)
          if (data.size > TOO_LARGE_LENGTH) {
            var omitData =
              String.format(
                  "*** Data cannot be displayed (reason: Data too large: %d) ***",
                  data.size,
                )
                .toByteArray(StandardCharsets.UTF_8)
            if (oneshot.getEncoder() == "HTTP") {
              val http = Http.create(data)
              http.body = omitData
              omitData = http.toByteArray()
            }
            client_packet!!.setDecodedData(omitData)
            client_packet!!.setModifiedData(omitData)
            client_packet!!.setSentData(omitData)
          }
          packets.update(client_packet!!)
          return encoded_data
        }

        @Throws(Exception::class) override fun onServerChunkSend(data: ByteArray): ByteArray = data

        @Throws(Exception::class)
        override fun onClientChunkSendForced(data: ByteArray): ByteArray? = null

        @Throws(Exception::class)
        override fun onServerChunkSendForced(data: ByteArray): ByteArray? = null

        @Throws(Exception::class)
        override fun onClientChunkArrived(data: ByteArray) {
          encoder.clientRequestArrived(data)
        }

        @Throws(Exception::class)
        override fun onServerChunkArrived(data: ByteArray) {
          encoder.serverResponseArrived(data)
        }

        @Throws(Exception::class)
        override fun onClientChunkPassThrough(): ByteArray? = encoder.passThroughClientRequest()

        @Throws(Exception::class)
        override fun onServerChunkPassThrough(): ByteArray? = encoder.passThroughServerResponse()

        @Throws(Exception::class)
        override fun onClientChunkAvailable(): ByteArray? = encoder.clientRequestAvailable()

        @Throws(Exception::class)
        override fun onServerChunkAvailable(): ByteArray? = encoder.serverResponseAvailable()

        @Throws(Exception::class)
        override fun onClientChunkFlowControl(data: ByteArray) {
          encoder.putToClientFlowControlledQueue(data)
        }

        @Throws(Exception::class)
        override fun onServerChunkFlowControl(data: ByteArray) {
          encoder.putToServerFlowControlledQueue(data)
        }

        @Throws(Exception::class)
        override fun closeClientChunkFlowControl() {
          encoder.closeClientFlowControlledQueue()
        }

        @Throws(Exception::class)
        override fun closeServerChunkFlowControl() {
          encoder.closeServerFlowControlledQueue()
        }

        @Throws(Exception::class)
        override fun getClientChunkFlowControlSink(): InputStream =
          encoder.getClientFlowControlledInputStream()

        @Throws(Exception::class)
        override fun getServerChunkFlowControlSink(): InputStream =
          encoder.getServerFlowControlledInputStream()
      }
    )
    return duplex
  }

  // Single-packet攻撃用のDuplexSync作成メソッド
  //
  // createDuplexSyncFromOneShotPacket（従来版）との主な違い：
  // 1. sendメソッドの禁止
  // sendメソッドは完全なリクエストを送信するが、Single-packet攻撃では
  // リクエストをフレーム単位で分割するため使用不可。
  // sendメソッド実行時にonClientChunkSendが例外をスロー。
  // 2. client_packetの作成タイミング変更
  // 従来版: sendメソッド → onClientChunkSendで作成
  // 本実装: onServerChunkReceivedで作成（sendメソッド未使用のため）
  @JvmStatic
  @Throws(Exception::class)
  fun createDuplexSyncForSinglePacketAttack(oneshot: OneShotPacket): DuplexSync {
    val duplex = DuplexSync(EndpointFactory.createFromOneShotPacket(oneshot))
    duplex.addDuplexEventListener(
      object : Duplex.DuplexEventListener {
        private val packets = Packets.getInstance()
        private val encoder =
          EncoderManager.getInstance().createInstance(oneshot.getEncoder() ?: "", oneshot.getAlpn())
        private var client_packet: Packet? = null
        private var server_packet: Packet? = null

        @Throws(Exception::class)
        override fun onClientPacketReceived(data: ByteArray): Int = data.size

        @Throws(Exception::class)
        override fun onServerPacketReceived(data: ByteArray): Int =
          encoder.checkResponseDelimiter(data)

        @Throws(Exception::class)
        override fun onClientChunkReceived(data: ByteArray): ByteArray = data

        @Throws(Exception::class)
        override fun onServerChunkReceived(data: ByteArray): ByteArray {
          client_packet =
            Packet(
              0,
              oneshot.getClient(),
              oneshot.getServer(),
              oneshot.getServerName() ?: "",
              oneshot.getUseSSL(),
              oneshot.getEncoder() ?: "",
              oneshot.getAlpn() ?: "",
              Packet.Direction.CLIENT,
              duplex.hashCode(),
              UniqueID.getInstance().createId(),
            )
          client_packet!!.setDecodedData(oneshot.getData())
          client_packet!!.setModifiedData(oneshot.getData())
          client_packet!!.setResend()
          client_packet!!.setReceivedData(oneshot.getData())
          client_packet!!.setSentData(encoder.encodeClientRequest(client_packet!!))
          packets.update(client_packet!!)

          val group_id = client_packet!!.getGroup()

          server_packet =
            Packet(
              0,
              oneshot.getClient(),
              oneshot.getServer(),
              oneshot.getServerName() ?: "",
              oneshot.getUseSSL(),
              oneshot.getEncoder() ?: "",
              oneshot.getAlpn() ?: "",
              Packet.Direction.SERVER,
              duplex.hashCode(),
              group_id,
            )
          packets.update(server_packet!!)
          server_packet!!.setReceivedData(data)
          if (data.size < SKIP_LENGTH) {
            packets.update(server_packet!!)
          }

          val decoded_data = encoder.decodeServerResponse(client_packet, server_packet!!)
          server_packet!!.setDecodedData(decoded_data)
          server_packet!!.setContentType(encoder.getContentType(client_packet, server_packet!!))

          if (server_packet!!.getContentType() != "") {
            client_packet!!.setContentType(server_packet!!.getContentType() ?: "")
            packets.update(client_packet!!)
          }

          server_packet!!.setModifiedData(decoded_data)
          packets.update(server_packet!!)
          if (decoded_data.isEmpty()) {
            server_packet!!.setModified()
            packets.update(server_packet!!)
            return ByteArray(0)
          }

          return decoded_data
        }

        @Throws(Exception::class)
        override fun onClientChunkSend(data: ByteArray): ByteArray {
          throw UnsupportedOperationException(
            "onClientChunkSend() should never be called in createDuplexSyncForSinglePacketAttack. " +
              "Use execFastSend() instead of send() because Single Packet Attack requires sending " +
              "partial requests, not complete ones. The send() method is designed for complete requests."
          )
        }

        @Throws(Exception::class)
        override fun onServerChunkSend(data: ByteArray): ByteArray {
          val encoded_data = encoder.encodeServerResponse(client_packet, server_packet!!)
          server_packet!!.setSentData(encoded_data)
          packets.update(server_packet!!)
          return encoded_data
        }

        @Throws(Exception::class)
        override fun onClientChunkSendForced(data: ByteArray): ByteArray? = null

        @Throws(Exception::class)
        override fun onServerChunkSendForced(data: ByteArray): ByteArray? = null

        @Throws(Exception::class)
        override fun onClientChunkArrived(data: ByteArray) {
          encoder.clientRequestArrived(data)
        }

        @Throws(Exception::class)
        override fun onServerChunkArrived(data: ByteArray) {
          encoder.serverResponseArrived(data)
        }

        @Throws(Exception::class)
        override fun onClientChunkPassThrough(): ByteArray? = encoder.passThroughClientRequest()

        @Throws(Exception::class)
        override fun onServerChunkPassThrough(): ByteArray? = encoder.passThroughServerResponse()

        @Throws(Exception::class)
        override fun onClientChunkAvailable(): ByteArray? = encoder.clientRequestAvailable()

        @Throws(Exception::class)
        override fun onServerChunkAvailable(): ByteArray? = encoder.serverResponseAvailable()

        @Throws(Exception::class)
        override fun onClientChunkFlowControl(data: ByteArray) {
          encoder.putToClientFlowControlledQueue(data)
        }

        @Throws(Exception::class)
        override fun onServerChunkFlowControl(data: ByteArray) {
          encoder.putToServerFlowControlledQueue(data)
        }

        @Throws(Exception::class)
        override fun closeClientChunkFlowControl() {
          encoder.closeClientFlowControlledQueue()
        }

        @Throws(Exception::class)
        override fun closeServerChunkFlowControl() {
          encoder.closeServerFlowControlledQueue()
        }

        @Throws(Exception::class)
        override fun getClientChunkFlowControlSink(): InputStream =
          encoder.getClientFlowControlledInputStream()

        @Throws(Exception::class)
        override fun getServerChunkFlowControlSink(): InputStream =
          encoder.getServerFlowControlledInputStream()
      }
    )
    return duplex
  }

  // original_duplexと接続を共有しているが、イベントリスナーは再送用のものに差し替えたDuplexを返す
  @JvmStatic
  @Throws(Exception::class)
  fun createDuplexFromOriginalDuplex(original_duplex: Duplex, oneshot: OneShotPacket): Duplex {
    val duplex = original_duplex.createSameConnectionDuplex()!!
    duplex.addDuplexEventListener(
      object : Duplex.DuplexEventListener {
        private val packets = Packets.getInstance()
        private val encoder =
          EncoderManager.getInstance().createInstance(oneshot.getEncoder() ?: "", oneshot.getAlpn())
        private var client_packet: Packet? = null
        private var server_packet: Packet? = null

        @Throws(Exception::class)
        override fun onClientPacketReceived(data: ByteArray): Int = data.size

        @Throws(Exception::class)
        override fun onServerPacketReceived(data: ByteArray): Int =
          encoder.checkResponseDelimiter(data)

        @Throws(Exception::class)
        override fun onClientChunkReceived(data: ByteArray): ByteArray {
          /* do nothing so far */
          return data
        }

        @Throws(Exception::class)
        override fun onServerChunkReceived(data: ByteArray): ByteArray {
          val group_id =
            if (client_packet != null) {
              client_packet!!.getGroup()
            } else {
              // サーバから先にレスポンスがあった場合
              UniqueID.getInstance().createId()
            }
          server_packet =
            Packet(
              0,
              oneshot.getClient(),
              oneshot.getServer(),
              oneshot.getServerName() ?: "",
              oneshot.getUseSSL(),
              oneshot.getEncoder() ?: "",
              oneshot.getAlpn() ?: "",
              Packet.Direction.SERVER,
              original_duplex.hashCode(),
              group_id,
            )
          // OneShotPacketからjob_idとtemporary_idを引き継ぎ
          server_packet!!.setJobId(oneshot.getJobId())
          server_packet!!.setTemporaryId(oneshot.getTemporaryId())
          packets.update(server_packet!!)
          server_packet!!.setReceivedData(data)
          if (data.size < SKIP_LENGTH) {
            packets.update(server_packet!!)
          }
          val decoded_data = encoder.decodeServerResponse(client_packet, server_packet!!)
          server_packet!!.setDecodedData(decoded_data)
          server_packet!!.setContentType(encoder.getContentType(client_packet, server_packet!!))
          if (server_packet!!.getContentType() != "") {
            client_packet!!.setContentType(server_packet!!.getContentType() ?: "")
            packets.update(client_packet!!)
          }
          server_packet!!.setModifiedData(decoded_data)
          packets.update(server_packet!!)
          if (decoded_data.isEmpty()) {
            /* drop */
            server_packet!!.setModified()
            packets.update(server_packet!!)
            return ByteArray(0)
          }
          return decoded_data
        }

        @Throws(Exception::class)
        override fun onClientChunkSend(data: ByteArray): ByteArray {
          client_packet =
            Packet(
              0,
              oneshot.getClient(),
              oneshot.getServer(),
              oneshot.getServerName() ?: "",
              oneshot.getUseSSL(),
              oneshot.getEncoder() ?: "",
              oneshot.getAlpn() ?: "",
              Packet.Direction.CLIENT,
              original_duplex.hashCode(),
              UniqueID.getInstance().createId(),
            )
          // OneShotPacketからjob_idとtemporary_idを引き継ぎ
          client_packet!!.setJobId(oneshot.getJobId())
          client_packet!!.setTemporaryId(oneshot.getTemporaryId())
          packets.update(client_packet!!)
          client_packet!!.setModified()
          client_packet!!.setDecodedData(data)
          client_packet!!.setModifiedData(data)
          if (data.size < SKIP_LENGTH) {
            packets.update(client_packet!!)
          }
          val encoded_data = encoder.encodeClientRequest(client_packet!!)
          client_packet!!.setSentData(encoded_data)
          packets.update(client_packet!!)
          return encoded_data
        }

        @Throws(Exception::class) override fun onServerChunkSend(data: ByteArray): ByteArray = data

        @Throws(Exception::class)
        override fun onClientChunkSendForced(data: ByteArray): ByteArray? = null

        @Throws(Exception::class)
        override fun onServerChunkSendForced(data: ByteArray): ByteArray? = null

        @Throws(Exception::class)
        override fun onClientChunkArrived(data: ByteArray) {
          encoder.clientRequestArrived(data)
        }

        @Throws(Exception::class)
        override fun onServerChunkArrived(data: ByteArray) {
          encoder.serverResponseArrived(data)
        }

        @Throws(Exception::class)
        override fun onClientChunkPassThrough(): ByteArray? = encoder.passThroughClientRequest()

        @Throws(Exception::class)
        override fun onServerChunkPassThrough(): ByteArray? = encoder.passThroughServerResponse()

        @Throws(Exception::class)
        override fun onClientChunkAvailable(): ByteArray? = encoder.clientRequestAvailable()

        @Throws(Exception::class)
        override fun onServerChunkAvailable(): ByteArray? = encoder.serverResponseAvailable()

        @Throws(Exception::class)
        override fun onClientChunkFlowControl(data: ByteArray) {
          encoder.putToClientFlowControlledQueue(data)
        }

        @Throws(Exception::class)
        override fun onServerChunkFlowControl(data: ByteArray) {
          encoder.putToServerFlowControlledQueue(data)
        }

        @Throws(Exception::class)
        override fun closeClientChunkFlowControl() {
          encoder.closeClientFlowControlledQueue()
        }

        @Throws(Exception::class)
        override fun closeServerChunkFlowControl() {
          encoder.closeServerFlowControlledQueue()
        }

        @Throws(Exception::class)
        override fun getClientChunkFlowControlSink(): InputStream =
          encoder.getClientFlowControlledInputStream()

        @Throws(Exception::class)
        override fun getServerChunkFlowControlSink(): InputStream =
          encoder.getServerFlowControlledInputStream()
      }
    )
    return duplex
  }
}
