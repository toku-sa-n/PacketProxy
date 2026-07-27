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
package packetproxy.common

import kotlin.test.assertEquals
import org.junit.jupiter.api.Test

class AmazonLexV2Test {
  @Test
  fun testToBytesAndFromBytes() {
    assertRoundTrip(
      arrayOf(
        AmazonLexV2.MessageHeader(":content-type", 7, "application/json"),
        AmazonLexV2.MessageHeader(":event-type", 7, "text"),
      ),
      "Hello World",
    )
  }

  @Test
  fun testToBytesAndFromBytesMultipleMessages() {
    val original =
      AmazonLexV2(
        arrayOf(
          AmazonLexV2.Message(
            arrayOf(AmazonLexV2.MessageHeader(":content-type", 7, "application/json")),
            "First message".toByteArray(),
          ),
          AmazonLexV2.Message(
            arrayOf(AmazonLexV2.MessageHeader(":event-type", 7, "audio")),
            "Second message".toByteArray(),
          ),
        )
      )
    assertEquals(original, AmazonLexV2.fromBytes(AmazonLexV2.toBytes(original)))
  }

  @Test
  fun testEmptyPayload() {
    assertRoundTrip(arrayOf(AmazonLexV2.MessageHeader(":event-type", 7, "heartbeat")), "")
  }

  private fun assertRoundTrip(headers: Array<AmazonLexV2.MessageHeader>, payload: String) {
    val original =
      AmazonLexV2(arrayOf(AmazonLexV2.Message(headers, payload.toByteArray(Charsets.UTF_8))))
    assertEquals(original, AmazonLexV2.fromBytes(AmazonLexV2.toBytes(original)))
  }
}
