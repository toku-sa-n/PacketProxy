/*
 * Copyright 2019,2023 DeNA Co., Ltd.
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

import java.nio.charset.StandardCharsets
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import packetproxy.websocket.OpCode
import packetproxy.websocket.WebSocket
import packetproxy.websocket.WebSocketFrame

/**
 * Tests that: 1. Text vs Binary opcode is preserved across decode/encode. 2. Empty-payload
 * WebSocket frames flow through the pipeline.
 */
class EncodeHTTPWebSocketOpCodeTest {
  @Test
  @Throws(Exception::class)
  fun frameAvailableRecordsTextOpcode() {
    val ws = WebSocket()
    ws.frameArrived(textFrameHello())
    assertArrayEquals("hello".toByteArray(StandardCharsets.UTF_8), ws.frameAvailable())
    assertEquals(OpCode.Text, ws.lastDequeuedOpCode())
  }

  @Test
  @Throws(Exception::class)
  fun frameAvailableRecordsBinaryOpcode() {
    val ws = WebSocket()
    ws.frameArrived(binaryFrameOneByte())
    assertArrayEquals(byteArrayOf(0x00), ws.frameAvailable())
    assertEquals(OpCode.Binary, ws.lastDequeuedOpCode())
  }

  @Test
  @Throws(Exception::class)
  fun encodeClientRequestPreservesTextOpcode() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    encoder.clientWebSocket.frameArrived(textFrameHello())
    val payload = encoder.clientRequestAvailable()
    val wire = encoder.encodeClientRequest(payload!!)
    assertEquals(finFirstByte(OpCode.Text), wire[0])
  }

  @Test
  @Throws(Exception::class)
  fun encodeClientRequestPreservesBinaryOpcode() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    encoder.clientWebSocket.frameArrived(binaryFrameOneByte())
    val payload = encoder.clientRequestAvailable()
    val wire = encoder.encodeClientRequest(payload!!)
    assertEquals(finFirstByte(OpCode.Binary), wire[0])
  }

  @Test
  @Throws(Exception::class)
  fun encodeServerResponsePreservesTextOpcode() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    encoder.serverWebSocket.frameArrived(textFrameHello())
    val payload = encoder.serverResponseAvailable()
    val wire = encoder.encodeServerResponse(payload!!)
    assertEquals(finFirstByte(OpCode.Text), wire[0])
  }

  @Test
  @Throws(Exception::class)
  fun parseThenSerializeRoundTripKeepsOpcode() {
    val text = WebSocketFrame.parse(textFrameHello())
    assertEquals(OpCode.Text, text.opcode)
    assertArrayEquals(
      textFrameHello(),
      WebSocketFrame.of(text.opcode, text.payload, false).getBytes(),
    )

    val bin = WebSocketFrame.parse(binaryFrameOneByte())
    assertEquals(OpCode.Binary, bin.opcode)
    assertArrayEquals(
      binaryFrameOneByte(),
      WebSocketFrame.of(bin.opcode, bin.payload, false).getBytes(),
    )
  }

  @Test
  @Throws(Exception::class)
  fun emptyPayloadTextFrameQueuesForDecode() {
    val ws = WebSocket()
    ws.frameArrived(textFrameEmptyPayload())
    assertArrayEquals(ByteArray(0), ws.passThroughFrame())
    assertArrayEquals(ByteArray(0), ws.frameAvailable())
  }

  @Test
  @Throws(Exception::class)
  fun emptyPayloadBinaryFrameQueuesForDecode() {
    val ws = WebSocket()
    ws.frameArrived(binaryFrameEmptyPayload())
    assertArrayEquals(ByteArray(0), ws.passThroughFrame())
    assertArrayEquals(ByteArray(0), ws.frameAvailable())
  }

  @Test
  @Throws(Exception::class)
  fun decodeClientRequestReturnsPlaceholderForEmptyPayload() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    val decoded = encoder.decodeClientRequest(ByteArray(0))
    assertArrayEquals(EncodeHTTPWebSocket.EMPTY_PAYLOAD_PLACEHOLDER, decoded)
  }

  @Test
  @Throws(Exception::class)
  fun decodeServerResponseReturnsPlaceholderForEmptyPayload() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    val decoded = encoder.decodeServerResponse(ByteArray(0))
    assertArrayEquals(EncodeHTTPWebSocket.EMPTY_PAYLOAD_PLACEHOLDER, decoded)
  }

  @Test
  @Throws(Exception::class)
  fun emptyPayloadClientRequestRoundTrip() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    encoder.clientWebSocket.frameArrived(textFrameEmptyPayload())
    encoder.clientWebSocket.passThroughFrame()
    val payload = encoder.clientRequestAvailable()
    assertNotNull(payload)
    assertArrayEquals(EncodeHTTPWebSocket.EMPTY_PAYLOAD_PLACEHOLDER, payload)
    val decoded = encoder.decodeClientRequest(payload!!)
    val wire = encoder.encodeClientRequest(decoded)
    // lastDequeuedOpCode preserves Text from the original frame
    assertEquals(finFirstByte(OpCode.Text), wire[0])
    assertEquals(0, payloadLen7Bits(wire[1]))
  }

  @Test
  @Throws(Exception::class)
  fun emptyPayloadServerResponseRoundTrip() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    encoder.serverWebSocket.frameArrived(binaryFrameEmptyPayload())
    encoder.serverWebSocket.passThroughFrame()
    val payload = encoder.serverResponseAvailable()
    assertNotNull(payload)
    assertArrayEquals(EncodeHTTPWebSocket.EMPTY_PAYLOAD_PLACEHOLDER, payload)
    val decoded = encoder.decodeServerResponse(payload!!)
    val wire = encoder.encodeServerResponse(decoded)
    assertArrayEquals(binaryFrameEmptyPayload(), wire)
  }

  @Test
  @Throws(Exception::class)
  fun editedPlaceholderClientRequestSendsNewContent() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    encoder.clientWebSocket.frameArrived(textFrameEmptyPayload())
    encoder.clientWebSocket.passThroughFrame()
    encoder.clientRequestAvailable()
    val userEdited = "hello".toByteArray(StandardCharsets.UTF_8)
    val wire = encoder.encodeClientRequest(userEdited)
    // lastDequeuedOpCode preserves Text from the original frame
    assertEquals(finFirstByte(OpCode.Text), wire[0])
    assertEquals(maskedPayloadLenByte(userEdited.size), wire[1])
  }

  /**
   * If the literal placeholder bytes are sent as payload without having come from an empty frame,
   * encode must not collapse them to a zero-length payload.
   */
  @Test
  @Throws(Exception::class)
  fun placeholderPayloadWithoutEmptyFrameFlagIsNotCollapsedToEmpty() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    encoder.clientWebSocket.frameArrived(textFrameHello())
    encoder.clientWebSocket.passThroughFrame()
    encoder.clientRequestAvailable()
    val wire = encoder.encodeClientRequest(EncodeHTTPWebSocket.EMPTY_PAYLOAD_PLACEHOLDER)
    assertEquals(finFirstByte(OpCode.Text), wire[0])
    assertNotEquals(0, payloadLen7Bits(wire[1]))
  }

  @Test
  @Throws(Exception::class)
  fun placeholderServerPayloadWithoutEmptyFrameFlagIsNotCollapsedToEmpty() {
    val encoder = TestEncoder()
    encoder.setBinaryStart(true)
    encoder.serverWebSocket.frameArrived(textFrameHello())
    encoder.serverWebSocket.passThroughFrame()
    encoder.serverResponseAvailable()
    val wire = encoder.encodeServerResponse(EncodeHTTPWebSocket.EMPTY_PAYLOAD_PLACEHOLDER)
    assertEquals(finFirstByte(OpCode.Text), wire[0])
    assertEquals(EncodeHTTPWebSocket.EMPTY_PAYLOAD_PLACEHOLDER.size, payloadLen7Bits(wire[1]))
  }

  private class TestEncoder @Throws(Exception::class) constructor() : EncodeHTTPWebSocket() {
    fun setBinaryStart(value: Boolean) {
      binary_start = value
    }
  }

  companion object {
    /** RFC 6455 frame byte 0: FIN (bit 7). */
    private const val WS_FIN_BIT = 0x80

    /** RFC 6455 frame byte 1: MASK (bit 7) for client-to-server frames. */
    private const val WS_MASK_BIT = 0x80

    /** RFC 6455 frame byte 1: bits 0–6 — payload length when that value is 0–125. */
    private const val WS_PAYLOAD_LEN_7BIT_MASK = 0x7F

    private fun finFirstByte(opcode: OpCode): Byte {
      return (WS_FIN_BIT or (opcode.code.toInt() and 0x0F)).toByte()
    }

    private fun unmaskedPayloadLenByte(payloadLength: Int): Byte {
      return (payloadLength and WS_PAYLOAD_LEN_7BIT_MASK).toByte()
    }

    private fun maskedPayloadLenByte(payloadLength: Int): Byte {
      return (WS_MASK_BIT or (payloadLength and WS_PAYLOAD_LEN_7BIT_MASK)).toByte()
    }

    private fun payloadLen7Bits(secondByte: Byte): Int {
      return secondByte.toInt() and WS_PAYLOAD_LEN_7BIT_MASK
    }

    /** Unmasked FIN+Text frame, payload "hello". */
    private fun textFrameHello(): ByteArray {
      val payload = "hello".toByteArray(StandardCharsets.UTF_8)
      val frame = ByteArray(2 + payload.size)
      frame[0] = finFirstByte(OpCode.Text)
      frame[1] = unmaskedPayloadLenByte(payload.size)
      System.arraycopy(payload, 0, frame, 2, payload.size)
      return frame
    }

    /** Unmasked FIN+Binary frame, single zero byte payload. */
    private fun binaryFrameOneByte(): ByteArray {
      return byteArrayOf(finFirstByte(OpCode.Binary), unmaskedPayloadLenByte(1), 0x00)
    }

    /** Unmasked FIN+Text frame, zero-length payload. */
    private fun textFrameEmptyPayload(): ByteArray {
      return byteArrayOf(finFirstByte(OpCode.Text), unmaskedPayloadLenByte(0))
    }

    /** Unmasked FIN+Binary frame, zero-length payload. */
    private fun binaryFrameEmptyPayload(): ByteArray {
      return byteArrayOf(finFirstByte(OpCode.Binary), unmaskedPayloadLenByte(0))
    }
  }
}
