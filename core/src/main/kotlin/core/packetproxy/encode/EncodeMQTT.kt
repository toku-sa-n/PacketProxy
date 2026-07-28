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
import packetproxy.model.Packet
import packetproxy.util.errWithStackTrace

class EncodeMQTT @Throws(Exception::class) constructor(ALPN: String?) : Encoder(ALPN) {
  override fun getName(): String = "MQTTv3.1"

  @Throws(Exception::class)
  override fun checkDelimiter(input_data: ByteArray): Int {
    var length = 0
    var digit: Byte
    var multiplier = 1
    var i = 0
    do {
      digit = input_data[++i]
      length += (digit.toInt() and 0x7F) * multiplier
      multiplier *= 0x80
    } while ((digit.toInt() and 0x80) != 0 && i < 4)

    // MQTT Header(1+i) + Body Length
    return 1 + i + length
  }

  @Throws(Exception::class)
  override fun encodeClientRequest(input_data: ByteArray): ByteArray = encode(input_data)

  @Throws(Exception::class)
  override fun decodeClientRequest(input_data: ByteArray): ByteArray = decode(input_data)

  @Throws(Exception::class)
  override fun encodeServerResponse(input_data: ByteArray): ByteArray = encode(input_data)

  @Throws(Exception::class)
  override fun decodeServerResponse(input_data: ByteArray): ByteArray = decode(input_data)

  override fun getSummarizedRequest(packet: Packet): String = getSummarizedMessage(packet)

  override fun getSummarizedResponse(packet: Packet): String = getSummarizedMessage(packet)

  @Throws(Exception::class)
  private fun encode(b: ByteArray): ByteArray {
    val m = parser.messageObject(String(b))
    return MQParser.encode(m).array()
  }

  @Throws(Exception::class)
  private fun decode(b: ByteArray): ByteArray {
    val m = MQParser.decode(Unpooled.copiedBuffer(b))
    return parser.jsonString(m).toByteArray()
  }

  private fun getSummarizedMessage(packet: Packet): String {
    val raw_data =
      if (packet.getSentData().isNotEmpty()) packet.getSentData() else packet.getReceivedData()
    if (raw_data.isEmpty()) return ""

    try {
      val message = MQParser.decode(Unpooled.copiedBuffer(raw_data))
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
