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

import java.nio.charset.StandardCharsets
import packetproxy.common.UniqueID
import packetproxy.encode.Encoder
import packetproxy.http.Http
import packetproxy.model.Packet
import packetproxy.model.PacketSummarizer
import packetproxy.model.Packets

/** Shared History recording helpers used by Duplex event listeners. */
class DuplexPacketHistory(
  private val uniqueId: UniqueID,
  private val packetSummarizer: PacketSummarizer,
) {
  // 10MB以上のパケットはHistoryには記録しない
  val TOO_LARGE_LENGTH = 10 * 1024 * 1024

  fun groupIdOrNew(clientPacket: Packet?): Long =
    if (clientPacket != null) {
      clientPacket.getGroup()
    } else {
      // サーバから先にレスポンスがあった場合
      uniqueId.createId()
    }

  fun syncContentTypeToClient(packets: Packets, clientPacket: Packet?, serverPacket: Packet) {
    if (clientPacket == null) {
      return
    }
    val contentType = serverPacket.getContentType() ?: ""
    if (contentType.isEmpty()) {
      return
    }
    clientPacket.setContentType(contentType)
    packets.updateContentType(clientPacket.getId(), contentType)
  }

  /**
   * Decodes a server response, records it in History once, and returns decoded data (empty if
   * dropped). Used by OneShot / SPA / OriginalDuplex listeners.
   */
  fun decodeAndRecordServerResponse(
    packets: Packets,
    encoder: Encoder,
    clientPacket: Packet?,
    serverPacket: Packet,
    data: ByteArray,
  ): ByteArray {
    serverPacket.setReceivedData(data)

    var decodedData = encoder.decodeServerResponse(clientPacket, serverPacket)
    serverPacket.setDecodedData(decodedData)
    serverPacket.setContentType(encoder.getContentType(clientPacket, serverPacket))
    syncContentTypeToClient(packets, clientPacket, serverPacket)

    serverPacket.setModifiedData(decodedData)
    if (decodedData.isEmpty()) {
      /* drop */
      serverPacket.setModified()
      serverPacket.refreshPersistedSummaries(packetSummarizer)
      packets.update(serverPacket)
      return ByteArray(0)
    }
    serverPacket.refreshPersistedSummaries(packetSummarizer)
    packets.update(serverPacket)
    return decodedData
  }

  /**
   * When data exceeds TOO_LARGE_LENGTH, replaces received/decoded/modified/sent with an omit
   * message. Returns true if omission was applied.
   */
  fun applyOmitIfTooLarge(packet: Packet, data: ByteArray, encoderName: String?): Boolean {
    if (data.size <= TOO_LARGE_LENGTH) {
      return false
    }
    var omitData =
      String.format("*** Data cannot be displayed (reason: Data too large: %d) ***", data.size)
        .toByteArray(StandardCharsets.UTF_8)
    if (encoderName == "HTTP") {
      try {
        var http = Http.create(data)
        http.body = omitData
        omitData = http.toByteArray()
      } catch (_: Exception) {
        // fall through with plain omit message
      }
    }
    packet.setReceivedData(omitData)
    packet.setDecodedData(omitData)
    packet.setModifiedData(omitData)
    packet.setSentData(omitData)
    return true
  }

  /**
   * Runs [persist] with large payloads omitted for History. Restores original stage data afterward
   * so subsequent encode/forward still sees the full payload.
   */
  fun <T> persistOmittingIfTooLarge(
    packet: Packet,
    data: ByteArray,
    encoderName: String?,
    persist: () -> T,
  ): T {
    if (data.size <= TOO_LARGE_LENGTH) {
      return persist()
    }
    val received = packet.getReceivedData()
    val decoded = packet.getDecodedData()
    val modified = packet.getModifiedData()
    val sent = packet.getSentData()
    applyOmitIfTooLarge(packet, data, encoderName)
    try {
      return persist()
    } finally {
      packet.setReceivedData(received)
      packet.setDecodedData(decoded)
      packet.setModifiedData(modified)
      packet.setSentData(sent)
    }
  }
}
