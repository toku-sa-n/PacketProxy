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
package packetproxy.encode

import com.mobius.software.mqtt.parser.MQJsonParser
import com.mobius.software.mqtt.parser.MQParser
import com.mobius.software.mqtt.parser.avps.MessageType
import com.mobius.software.mqtt.parser.header.impl.Puback
import com.mobius.software.mqtt.parser.header.impl.Pubcomp
import com.mobius.software.mqtt.parser.header.impl.Publish
import com.mobius.software.mqtt.parser.header.impl.Pubrec
import com.mobius.software.mqtt.parser.header.impl.Pubrel
import com.mobius.software.mqtt.parser.header.impl.Suback
import com.mobius.software.mqtt.parser.header.impl.Subscribe
import com.mobius.software.mqtt.parser.header.impl.Unsuback
import com.mobius.software.mqtt.parser.header.impl.Unsubscribe
import io.netty.buffer.Unpooled
import packetproxy.http.Http
import packetproxy.model.Packet
import packetproxy.util.errWithStackTrace

class EncodeMQTTWebSocket @Throws(Exception::class) constructor(ALPN: String?) :
  EncodeHTTPWebSocket(ALPN) {
  override fun getName(): String = "MQTTv3.1 over WebSocket"

  @Throws(Exception::class)
  override fun getContentType(input_data: ByteArray): String {
    // Java shadowed parent binary_start with an always-false field, so this always took the HTTP
    // branch.
    val http = Http.create(input_data)
    return http.getFirstHeader("Content-Type")
  }

  @Throws(Exception::class)
  override fun decodeWebsocketRequest(input: ByteArray): ByteArray = decodeMQTT(input)

  @Throws(Exception::class)
  override fun encodeWebsocketRequest(input: ByteArray): ByteArray = encodeMQTT(input)

  @Throws(Exception::class)
  override fun decodeWebsocketResponse(input: ByteArray): ByteArray = decodeMQTT(input)

  @Throws(Exception::class)
  override fun encodeWebsocketResponse(input: ByteArray): ByteArray = encodeMQTT(input)

  override fun getSummarizedRequest(packet: Packet): String {
    if (packet.getDecodedData().isEmpty() && packet.getModifiedData().isEmpty()) {
      return ""
    }
    val data =
      if (packet.getDecodedData().isNotEmpty()) packet.getDecodedData()
      else packet.getModifiedData()

    try {
      if (data.isEmpty()) throw Exception()
      val http = Http.create(data)
      val method = http.method
      val url = http.getURL(packet.getServerPort(), packet.getUseSSL())
      if (method == null) return getSummarizedMessage(encodeMQTT(data))
      return "$method $url"
    } catch (e: Exception) {
      return "Headlineを生成できません・・・"
    }
  }

  override fun getSummarizedResponse(packet: Packet): String {
    if (packet.getDecodedData().isEmpty() && packet.getModifiedData().isEmpty()) {
      return ""
    }
    val data =
      if (packet.getDecodedData().isNotEmpty()) packet.getDecodedData()
      else packet.getModifiedData()

    try {
      if (data.isEmpty()) throw Exception()
      val http = Http.create(data)
      if (http.statusCode.isEmpty()) return getSummarizedMessage(encodeMQTT(data))
      return http.statusCode
    } catch (e: Exception) {
      return "Headlineを生成できません・・・"
    }
  }

  @Throws(Exception::class)
  private fun encodeMQTT(b: ByteArray): ByteArray {
    val json = String(b)
    val m = parser.messageObject(json)
    return MQParser.encode(m).array()
  }

  @Throws(Exception::class)
  private fun decodeMQTT(b: ByteArray): ByteArray {
    val m = MQParser.decode(Unpooled.copiedBuffer(b))
    return parser.jsonString(m).toByteArray()
  }

  private fun getSummarizedMessage(data: ByteArray): String {
    try {
      val message = MQParser.decode(Unpooled.copiedBuffer(data))
      val cmd = message.getType().toString()
      var msgId: Int? = null
      when (message.getType()) {
        // Has Message ID
        MessageType.PUBLISH -> msgId = (message as Publish).packetID
        MessageType.PUBACK -> msgId = (message as Puback).packetID
        MessageType.PUBREC -> msgId = (message as Pubrec).packetID
        MessageType.PUBREL -> msgId = (message as Pubrel).packetID
        MessageType.PUBCOMP -> msgId = (message as Pubcomp).packetID
        MessageType.SUBSCRIBE -> msgId = (message as Subscribe).packetID
        MessageType.SUBACK -> msgId = (message as Suback).packetID
        MessageType.UNSUBSCRIBE -> msgId = (message as Unsubscribe).packetID
        MessageType.UNSUBACK -> msgId = (message as Unsuback).packetID
        else -> {}
      }
      return if (msgId != null) "$msgId: $cmd" else cmd
    } catch (e: Exception) {
      errWithStackTrace(e)
      return "Failed to Parse as MQTT Protocol"
    }
  }

  companion object {
    @JvmField var parser = MQJsonParser()
  }
}
