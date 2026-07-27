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
import packetproxy.model.Packets

/** Shared History recording helpers used by Duplex event listeners. */
internal object DuplexPacketHistory {
  // 1MB以上のパケットは最後のタイミングだけHistoryに記録する、それ未満はパケットが更新されるたびにHistoryを更新する
  const val SKIP_LENGTH = 1 * 1024 * 1024
  // 10MB以上のパケットはHistoryには記録しない
  const val TOO_LARGE_LENGTH = 10 * 1024 * 1024

  fun updateIfSmall(packets: Packets, packet: Packet, dataSize: Int) {
    if (dataSize < SKIP_LENGTH) {
      packets.update(packet)
    }
  }

  fun groupIdOrNew(clientPacket: Packet?): Long =
    if (clientPacket != null) {
      clientPacket.getGroup()
    } else {
      // サーバから先にレスポンスがあった場合
      UniqueID.getInstance().createId()
    }

  fun syncContentTypeToClient(packets: Packets, clientPacket: Packet?, serverPacket: Packet) {
    if (serverPacket.getContentType() != "") {
      clientPacket!!.setContentType(serverPacket.getContentType() ?: "")
      packets.update(clientPacket)
    }
  }

  /**
   * Decodes a server response, records it in History, and returns decoded data (empty if dropped).
   * Used by OneShot / SPA / OriginalDuplex listeners.
   */
  fun decodeAndRecordServerResponse(
    packets: Packets,
    encoder: Encoder,
    clientPacket: Packet?,
    serverPacket: Packet,
    data: ByteArray,
  ): ByteArray {
    packets.update(serverPacket)
    serverPacket.setReceivedData(data)
    updateIfSmall(packets, serverPacket, data.size)

    var decodedData = encoder.decodeServerResponse(clientPacket, serverPacket)
    serverPacket.setDecodedData(decodedData)
    serverPacket.setContentType(encoder.getContentType(clientPacket, serverPacket))
    syncContentTypeToClient(packets, clientPacket, serverPacket)

    serverPacket.setModifiedData(decodedData)
    packets.update(serverPacket)
    if (decodedData.isEmpty()) {
      /* drop */
      serverPacket.setModified()
      packets.update(serverPacket)
      return ByteArray(0)
    }
    return decodedData
  }

  /**
   * When data exceeds TOO_LARGE_LENGTH, replaces decoded/modified/sent display data with an omit
   * message. Returns true if omission was applied.
   */
  fun applyOmitIfTooLarge(clientPacket: Packet, data: ByteArray, encoderName: String?): Boolean {
    if (data.size <= TOO_LARGE_LENGTH) {
      return false
    }
    var omitData =
      String.format("*** Data cannot be displayed (reason: Data too large: %d) ***", data.size)
        .toByteArray(StandardCharsets.UTF_8)
    if (encoderName == "HTTP") {
      var http = Http.create(data)
      http.body = omitData
      omitData = http.toByteArray()
    }
    clientPacket.setDecodedData(omitData)
    clientPacket.setModifiedData(omitData)
    clientPacket.setSentData(omitData)
    return true
  }
}
