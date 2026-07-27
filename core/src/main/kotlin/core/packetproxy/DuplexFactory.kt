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
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import packetproxy.common.CryptUtils
import packetproxy.common.Endpoint
import packetproxy.common.EndpointFactory
import packetproxy.common.SSLSocketEndpoint
import packetproxy.common.UniqueID
import packetproxy.controller.InterceptController
import packetproxy.encode.Encoder
import packetproxy.http.Http
import packetproxy.http.HttpsProxySocketEndpoint
import packetproxy.model.Modifications
import packetproxy.model.OneShotPacket
import packetproxy.model.Packet
import packetproxy.model.Packets
import packetproxy.model.Servers

object DuplexFactory {
  @JvmStatic
  @Throws(Exception::class)
  fun createDuplexSync(
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    encoder_name: String,
    ALPN: String?,
  ): DuplexSync {
    var duplex = DuplexSync(server_endpoint)
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
    var duplex = DuplexAsync(client_endpoint, server_endpoint)
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
    var duplex = DuplexAsync(client_endpoint, server_endpoint)
    prepareDuplex(duplex, client_endpoint, server_endpoint, encoder_name, ALPN)
    return duplex
  }

  @JvmStatic
  @Throws(Exception::class)
  fun createDuplexSyncFromOneShotPacket(oneshot: OneShotPacket): DuplexSync {
    var duplex = DuplexSync(EndpointFactory.createFromOneShotPacket(oneshot))
    var encoder =
      EncoderManager.getInstance().createInstance(oneshot.getEncoder() ?: "", oneshot.getAlpn())
    duplex.addDuplexEventListener(
      duplexEventListener(encoder, createOneShotHandlers(duplex.hashCode(), oneshot, encoder))
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
    var duplex = DuplexSync(EndpointFactory.createFromOneShotPacket(oneshot))
    var encoder =
      EncoderManager.getInstance().createInstance(oneshot.getEncoder() ?: "", oneshot.getAlpn())
    duplex.addDuplexEventListener(
      duplexEventListener(encoder, createSpaHandlers(duplex.hashCode(), oneshot, encoder))
    )
    return duplex
  }

  // original_duplexと接続を共有しているが、イベントリスナーは再送用のものに差し替えたDuplexを返す
  @JvmStatic
  @Throws(Exception::class)
  fun createDuplexFromOriginalDuplex(original_duplex: Duplex, oneshot: OneShotPacket): Duplex {
    var duplex = original_duplex.createSameConnectionDuplex()!!
    var encoder =
      EncoderManager.getInstance().createInstance(oneshot.getEncoder() ?: "", oneshot.getAlpn())
    duplex.addDuplexEventListener(
      duplexEventListener(
        encoder,
        createOriginalDuplexHandlers(original_duplex.hashCode(), oneshot, encoder),
      )
    )
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
    var client_addr = client_endpoint.getAddress()
    var server_addr = server_endpoint.getAddress()
    var use_ssl =
      server_endpoint is SSLSocketEndpoint || server_endpoint is HttpsProxySocketEndpoint
    var encoder = EncoderManager.getInstance().createInstance(encoder_name, ALPN)

    duplex.addDuplexEventListener(
      duplexEventListener(
        encoder,
        createProxyHandlers(
          duplex,
          client_addr,
          server_addr,
          server_endpoint.getName() ?: "",
          use_ssl,
          encoder_name,
          ALPN ?: "",
          encoder,
        ),
      )
    )
  }

  private fun createProxyHandlers(
    duplex: Duplex,
    client_addr: InetSocketAddress,
    server_addr: InetSocketAddress,
    server_name: String,
    use_ssl: Boolean,
    encoder_name: String,
    alpn: String,
    encoder: Encoder,
  ): DuplexEventHandlers {
    var packets = Packets.getInstance()
    var mods = Modifications.getInstance()
    var client_packet: Packet? = null
    var server_packet: Packet? = null

    fun newPacket(direction: Packet.Direction, groupId: Long): Packet =
      Packet(
        0,
        client_addr,
        server_addr,
        server_name,
        use_ssl,
        encoder_name,
        alpn,
        direction,
        duplex.hashCode(),
        groupId,
      )

    return DuplexEventHandlers(
      onClientPacketReceived = { data -> encoder.checkRequestDelimiter(data) },
      onServerPacketReceived = { data -> encoder.checkResponseDelimiter(data) },
      onClientChunkReceived = clientChunkReceived@{ data ->
          var initialGroupId = UniqueID.getInstance().createId()
          client_packet = newPacket(Packet.Direction.CLIENT, initialGroupId)
          client_packet!!.setReceivedData(data)
          var decoded_data = encoder.decodeClientRequest(client_packet!!)
          client_packet!!.setDecodedData(decoded_data)
          // groupIdはencoder.setGroupId()で変更される可能性があるため、
          // GUIHistoryへの通知（packets.update）はgroupId確定後に行う
          encoder.setGroupId(client_packet!!) /* 実行するのはsetDecodedDataのあと */
          DuplexPacketHistory.updateIfSmall(packets, client_packet!!, data.size)

          var server = Servers.getInstance().queryByAddress(server_addr)
          decoded_data = mods.replaceOnRequest(decoded_data, server, client_packet!!)

          var decoded_hash = CryptUtils.sha1(decoded_data)

          var intercepted_data = runBlocking {
            InterceptController.getInstance().received(decoded_data, server, client_packet!!).fold({
              ByteArray(0)
            }) {
              it
            }
          }

          var intercepted_hash = CryptUtils.sha1(intercepted_data)
          client_packet!!.setModifiedData(intercepted_data)
          if (intercepted_data.isNotEmpty() && !Arrays.equals(decoded_hash, intercepted_hash)) {
            client_packet!!.setModified()
          }
          DuplexPacketHistory.updateIfSmall(packets, client_packet!!, data.size)
          if (intercepted_data.isEmpty()) {
            /* drop */
            client_packet!!.setModified()
            packets.update(client_packet!!)
            return@clientChunkReceived ByteArray(0)
          }
          intercepted_data
        },
      onServerChunkReceived = serverChunkReceived@{ data ->
          var group_id = DuplexPacketHistory.groupIdOrNew(client_packet)
          server_packet = newPacket(Packet.Direction.SERVER, group_id)
          packets.update(server_packet!!)
          server_packet!!.setReceivedData(data)
          DuplexPacketHistory.updateIfSmall(packets, server_packet!!, data.size)
          var decoded_data = encoder.decodeServerResponse(client_packet, server_packet!!)
          server_packet!!.setDecodedData(decoded_data)
          encoder.setGroupId(server_packet!!) /* 実行するのはsetDecodedDataのあと */
          server_packet!!.setContentType(encoder.getContentType(client_packet, server_packet!!))
          DuplexPacketHistory.updateIfSmall(packets, server_packet!!, data.size)
          DuplexPacketHistory.syncContentTypeToClient(packets, client_packet, server_packet!!)

          var server = Servers.getInstance().queryByAddress(server_addr)
          decoded_data = mods.replaceOnResponse(decoded_data, server, server_packet!!)

          var decoded_hash = CryptUtils.sha1(decoded_data)

          var intercepted_data = runBlocking {
            InterceptController.getInstance()
              .received(decoded_data, server, client_packet!!, server_packet!!)
              .fold({ ByteArray(0) }) { it }
          }

          var intercepted_hash = CryptUtils.sha1(intercepted_data)
          server_packet!!.setModifiedData(intercepted_data)
          if (intercepted_data.isNotEmpty() && !Arrays.equals(decoded_hash, intercepted_hash)) {
            server_packet!!.setModified()
          }
          DuplexPacketHistory.updateIfSmall(packets, server_packet!!, data.size)
          if (intercepted_data.isEmpty()) {
            /* drop */
            server_packet!!.setModified()
            packets.update(server_packet!!)
            return@serverChunkReceived ByteArray(0)
          }
          intercepted_data
        },
      onClientChunkSend = { _ ->
        var encoded_data = encoder.encodeClientRequest(client_packet!!)
        client_packet!!.setSentData(encoded_data)
        packets.update(client_packet!!)
        encoded_data
      },
      onServerChunkSend = { _ ->
        var encoded_data = encoder.encodeServerResponse(client_packet, server_packet!!)

        // 画像データの場合には、ディスクスペース節約のためにDBに保存しない
        if ((server_packet!!.getContentType() ?: "").startsWith("image")) {
          var http = Http.create(server_packet!!.getDecodedData())
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
        encoded_data
      },
      onClientChunkSendForced = { data ->
        var forcedClientPacket =
          newPacket(Packet.Direction.CLIENT, UniqueID.getInstance().createId())
        packets.update(forcedClientPacket)
        forcedClientPacket.setModified()
        forcedClientPacket.setDecodedData(data)
        DuplexPacketHistory.updateIfSmall(packets, forcedClientPacket, data.size)
        forcedClientPacket.setModifiedData(data)
        forcedClientPacket.setModifiedData(
          encoder.procBeforeResendClientRequest(forcedClientPacket)
        )
        DuplexPacketHistory.updateIfSmall(packets, forcedClientPacket, data.size)
        var encoded_data = encoder.encodeClientRequest(forcedClientPacket)
        forcedClientPacket.setSentData(encoded_data)
        packets.update(forcedClientPacket)
        encoded_data
      },
      onServerChunkSendForced = { data ->
        var group_id = DuplexPacketHistory.groupIdOrNew(client_packet)
        var forcedServerPacket = newPacket(Packet.Direction.SERVER, group_id)
        packets.update(forcedServerPacket)
        forcedServerPacket.setDecodedData(data)
        DuplexPacketHistory.updateIfSmall(packets, forcedServerPacket, data.size)
        forcedServerPacket.setModifiedData(data)
        forcedServerPacket.setModifiedData(
          encoder.procBeforeResendServerResponse(forcedServerPacket)
        )
        DuplexPacketHistory.updateIfSmall(packets, forcedServerPacket, data.size)
        var encoded_data = encoder.encodeServerResponse(client_packet, forcedServerPacket)
        forcedServerPacket.setSentData(encoded_data)
        packets.update(forcedServerPacket)
        encoded_data
      },
    )
  }

  private fun createOneShotHandlers(
    connectionId: Int,
    oneshot: OneShotPacket,
    encoder: Encoder,
  ): DuplexEventHandlers {
    var packets = Packets.getInstance()
    var client_packet: Packet? = null
    var server_packet: Packet? = null

    return DuplexEventHandlers(
      onClientPacketReceived = { data -> data.size },
      onServerPacketReceived = { data -> encoder.checkResponseDelimiter(data) },
      onClientChunkReceived = { data ->
        /* do nothing so far */
        data
      },
      onServerChunkReceived = { data ->
        var group_id = DuplexPacketHistory.groupIdOrNew(client_packet)
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
            connectionId,
            group_id,
          )
        // OneShotPacketからjob_idとtemporary_idを引き継ぎ
        server_packet!!.setJobId(oneshot.getJobId())
        server_packet!!.setTemporaryId(oneshot.getTemporaryId())
        DuplexPacketHistory.decodeAndRecordServerResponse(
          packets,
          encoder,
          client_packet,
          server_packet!!,
          data,
        )
      },
      onClientChunkSend = { data ->
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
            connectionId,
            UniqueID.getInstance().createId(),
          )
        // OneShotPacketからjob_idとtemporary_idを引き継ぎ
        client_packet!!.setJobId(oneshot.getJobId())
        client_packet!!.setTemporaryId(oneshot.getTemporaryId())
        client_packet!!.setModified()
        client_packet!!.setReceivedData(data)
        client_packet!!.setDecodedData(data)
        client_packet!!.setModifiedData(data)
        DuplexPacketHistory.updateIfSmall(packets, client_packet!!, data.size)
        var encoded_data = encoder.encodeClientRequest(client_packet!!)
        client_packet!!.setSentData(encoded_data)
        DuplexPacketHistory.applyOmitIfTooLarge(client_packet!!, data, oneshot.getEncoder())
        packets.update(client_packet!!)
        encoded_data
      },
      onServerChunkSend = { data -> data },
      onClientChunkSendForced = { _ -> null },
      onServerChunkSendForced = { _ -> null },
    )
  }

  private fun createSpaHandlers(
    connectionId: Int,
    oneshot: OneShotPacket,
    encoder: Encoder,
  ): DuplexEventHandlers {
    var packets = Packets.getInstance()
    var client_packet: Packet? = null
    var server_packet: Packet? = null

    return DuplexEventHandlers(
      onClientPacketReceived = { data -> data.size },
      onServerPacketReceived = { data -> encoder.checkResponseDelimiter(data) },
      onClientChunkReceived = { data -> data },
      onServerChunkReceived = { data ->
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
            connectionId,
            UniqueID.getInstance().createId(),
          )
        client_packet!!.setDecodedData(oneshot.getData())
        client_packet!!.setModifiedData(oneshot.getData())
        client_packet!!.setResend()
        client_packet!!.setReceivedData(oneshot.getData())
        client_packet!!.setSentData(encoder.encodeClientRequest(client_packet!!))
        packets.update(client_packet!!)

        var group_id = client_packet!!.getGroup()

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
            connectionId,
            group_id,
          )
        DuplexPacketHistory.decodeAndRecordServerResponse(
          packets,
          encoder,
          client_packet,
          server_packet!!,
          data,
        )
      },
      onClientChunkSend = { _ ->
        throw UnsupportedOperationException(
          "onClientChunkSend() should never be called in createDuplexSyncForSinglePacketAttack. " +
            "Use execFastSend() instead of send() because Single Packet Attack requires sending " +
            "partial requests, not complete ones. The send() method is designed for complete requests."
        )
      },
      onServerChunkSend = { _ ->
        var encoded_data = encoder.encodeServerResponse(client_packet, server_packet!!)
        server_packet!!.setSentData(encoded_data)
        packets.update(server_packet!!)
        encoded_data
      },
      onClientChunkSendForced = { _ -> null },
      onServerChunkSendForced = { _ -> null },
    )
  }

  private fun createOriginalDuplexHandlers(
    connectionId: Int,
    oneshot: OneShotPacket,
    encoder: Encoder,
  ): DuplexEventHandlers {
    var packets = Packets.getInstance()
    var client_packet: Packet? = null
    var server_packet: Packet? = null

    return DuplexEventHandlers(
      onClientPacketReceived = { data -> data.size },
      onServerPacketReceived = { data -> encoder.checkResponseDelimiter(data) },
      onClientChunkReceived = { data ->
        /* do nothing so far */
        data
      },
      onServerChunkReceived = { data ->
        var group_id = DuplexPacketHistory.groupIdOrNew(client_packet)
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
            connectionId,
            group_id,
          )
        // OneShotPacketからjob_idとtemporary_idを引き継ぎ
        server_packet!!.setJobId(oneshot.getJobId())
        server_packet!!.setTemporaryId(oneshot.getTemporaryId())
        DuplexPacketHistory.decodeAndRecordServerResponse(
          packets,
          encoder,
          client_packet,
          server_packet!!,
          data,
        )
      },
      onClientChunkSend = { data ->
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
            connectionId,
            UniqueID.getInstance().createId(),
          )
        // OneShotPacketからjob_idとtemporary_idを引き継ぎ
        client_packet!!.setJobId(oneshot.getJobId())
        client_packet!!.setTemporaryId(oneshot.getTemporaryId())
        packets.update(client_packet!!)
        client_packet!!.setModified()
        client_packet!!.setDecodedData(data)
        client_packet!!.setModifiedData(data)
        DuplexPacketHistory.updateIfSmall(packets, client_packet!!, data.size)
        var encoded_data = encoder.encodeClientRequest(client_packet!!)
        client_packet!!.setSentData(encoded_data)
        packets.update(client_packet!!)
        encoded_data
      },
      onServerChunkSend = { data -> data },
      onClientChunkSendForced = { _ -> null },
      onServerChunkSendForced = { _ -> null },
    )
  }
}
